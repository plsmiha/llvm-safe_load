#include "RISCV.h"
#include "RISCVInstrInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SparseBitVector.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;


//  this hardens every load unconditionally
static cl::opt<bool> EnableSafeLoad(
    "riscv-slh",
    cl::desc("Enable SLH load hardening (see riscv-slh-opt-* for the "
             "optimized variant)"),
    cl::init(false));

// Optimization 1: a load whose base register was itself produced
// by a load already known safe earlier in the same basic block doesn't need hardening: once the first load in the chain has retired, every
static cl::opt<bool> SkipDependentLoads(
    "riscv-slh-opt-dependent",
    cl::desc("Don't harden a load whose address comes from another load "
             "already known safe earlier in the same basic block"),
    cl::init(false));

// Optimization 2: a load addressed as a constant offset from sp/fp
// sp/fp is implicitly "safe"
static cl::opt<bool> SkipStackConstLoads(
    "riscv-slh-opt-stack",
    cl::desc("Don't harden a load addressed as a constant offset from sp/fp"),
    cl::init(false));

#define DEBUG_TYPE "riscv-safe-load"
#define RISCV_SAFE_LOAD_NAME "RISC-V unconditional SLH"

namespace {
                    // base class for passes that run once per function,
                    //on real target instructions (post instruction-selection)
class RISCVSafeLoad : public MachineFunctionPass {
public:
  static char ID;
  RISCVSafeLoad() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override;
  StringRef getPassName() const override { return RISCV_SAFE_LOAD_NAME; }
};

}

char RISCVSafeLoad::ID = 0; // pass the address of ID = unique tag

INITIALIZE_PASS(RISCVSafeLoad, DEBUG_TYPE, RISCV_SAFE_LOAD_NAME, false, false)

FunctionPass *llvm::createRISCVSafeLoadPass() { return new RISCVSafeLoad(); }

// Map each integer load opcode to its safe-load equivalent.
static unsigned getSafeLoadOpcode(unsigned Opcode) {
  switch (Opcode) {
  case RISCV::LB:  return RISCV::SAFE_LB;
  case RISCV::LH:  return RISCV::SAFE_LH;
  case RISCV::LW:  return RISCV::SAFE_LW;
  case RISCV::LD:  return RISCV::SAFE_LD;
  case RISCV::LBU: return RISCV::SAFE_LBU;
  case RISCV::LHU: return RISCV::SAFE_LHU;
  case RISCV::LWU: return RISCV::SAFE_LWU;
  case RISCV::FLW: return RISCV::SAFE_FLW;
  case RISCV::FLD: return RISCV::SAFE_FLD;
  default:         return 0;
  }
}


static void clearReg(SparseBitVector<> &SafeRegs, Register Reg, const TargetRegisterInfo *TRI) {
  SmallVector<unsigned, 4> ToReset;
  for (unsigned R : SafeRegs)
    if (TRI->regsOverlap(Register(R), Reg)) // to solve register aliasing issues and keep consistency
      ToReset.push_back(R);
  for (unsigned R : ToReset)
    SafeRegs.reset(R);
}

static bool isRegSafe(const SparseBitVector<> &SafeRegs, Register Reg, const TargetRegisterInfo *TRI) {
  for (unsigned R : SafeRegs)
    if (TRI->regsOverlap(Register(R), Reg))
      return true;
  return false;
}

// Optimised
static bool hardenLoadsOptimized(MachineFunction &MF) {
  const RISCVInstrInfo *TII =MF.getSubtarget<RISCVSubtarget>().getInstrInfo();
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();

  // x8 ="fp" only when this function actually reserves it as such;
  // otherwise it's just an ordinary callee-saved GPR  sp no ambiguity
  bool HasFP = MF.getSubtarget<RISCVSubtarget>().getFrameLowering()->hasFP(MF);

  bool MadeChange = false;
  for (MachineBasicBlock &MBB : MF) {
    // Reset per block
    SparseBitVector<> SafeRegs;

    //Stack optimization + Inheritance optimization:  sp/fp are implicitly safe,
    //useful for more than 12 bit immidate but only wokrs when SkipDependentLoads
    if (SkipStackConstLoads) {
      SafeRegs.set(RISCV::X2);
      if (HasFP)
        SafeRegs.set(RISCV::X8);
    }

    for (MachineInstr &MI : MBB) {
      unsigned SafeOpc = getSafeLoadOpcode(MI.getOpcode());

      // LOADS
      if (SafeOpc) {
        Register Dst = MI.getOperand(0).getReg();
        Register Base = MI.getOperand(1).getReg();

        bool IsDependent = SkipDependentLoads && isRegSafe(SafeRegs, Base, TRI);
        bool IsConstStack = SkipStackConstLoads &&
                            (Base == RISCV::X2 || (HasFP && Base == RISCV::X8));

        if (!(IsDependent || IsConstStack)) {
          //NAIVE or not inherently safe          
          MI.setDesc(TII->get(SafeOpc));
          MadeChange = true;
        }
        // destination is safe from now on or inherently 
        clearReg(SafeRegs, Dst, TRI);
        SafeRegs.set(Dst.id());
        continue;
      }

      // NOT LOADS 
  
      if (SkipDependentLoads) {
        bool ResultSafe = !MI.isCall() &&
            llvm::any_of(MI.operands(), [&](const MachineOperand &MO) {
                                 //MI reads this reg
              return MO.isReg() && MO.isUse() && MO.getReg().isPhysical() &&
                     isRegSafe(SafeRegs, MO.getReg(), TRI);
            });

        // not in slh    
        for (const MachineOperand &MO : MI.operands()) {
          //- CALLS (calls aren't terminators -same bb)
          if (MO.isRegMask()) { //is this particular operand a regmask
            SmallVector<unsigned, 4> ToReset; // not allowed to change while iterating
            for (unsigned R : SafeRegs)
              if (MO.clobbersPhysReg(Register(R))) // asks the regmask operand if this register is in the clobber list
                //clobbered means the previous value in a register is destroyed/overwritten - just coller saved
              ToReset.push_back(R);
            for (unsigned R : ToReset)
              SafeRegs.reset(R);
                                  // are u being written
          } else if (MO.isReg() && MO.isDef() && MO.getReg().isPhysical()) {
            //- WRITES to a register
            //es add a0, a1, a2 — a0 is being written, a1 and a2 are being read
            clearReg(SafeRegs, MO.getReg(), TRI);
          }
        }

        //if any of the read operands is safe -> def is safe
        if (ResultSafe)
          for (const MachineOperand &MO : MI.operands())
            if (MO.isReg() && MO.isDef() && MO.getReg().isPhysical())
              SafeRegs.set(MO.getReg().id());
      }
    }
  }
  return MadeChange;
}


// Naive path:  swap every load
static bool hardenAllLoadsNaive(MachineFunction &MF) {

  const RISCVInstrInfo *TII = MF.getSubtarget<RISCVSubtarget>().getInstrInfo();
  bool MadeChange = false;

  for (MachineBasicBlock &MBB : MF)
    for (MachineInstr &MI : MBB)
      if (unsigned SafeOpc = getSafeLoadOpcode(MI.getOpcode())) {
        //replace with
        MI.setDesc(TII->get(SafeOpc));
         // get the instruction corresponding to this opcode from the         
                // from the build time TableGen lookup table (.td)
        MadeChange = true;
      }
  return MadeChange;
}


// inherited predifined function, main of the pass  
bool RISCVSafeLoad::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableSafeLoad)
    return false;
  if (!SkipDependentLoads && !SkipStackConstLoads)
    return hardenAllLoadsNaive(MF);
  return hardenLoadsOptimized(MF);
}
