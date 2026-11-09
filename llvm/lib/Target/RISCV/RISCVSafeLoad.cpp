#include "RISCV.h"
#include "RISCVInstrInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SparseBitVector.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"

using namespace llvm;



// Base : hardens every load unconditionally
static cl::opt<bool> EnableSafeLoad(
    "riscv-slh",
    cl::desc("Enable SLH load hardening (see riscv-slh-opt-* for the "
             "optimized variant)"),
    cl::init(false));

// Optimization 1: a load addressed as a constant offset from sp/fp
// sp/fp is implicitly "safe"
static cl::opt<bool> SkipStackConstLoads(
    "riscv-slh-opt-stack",
    cl::desc("Don't harden a load addressed as a constant offset from sp/fp"),
    cl::init(false));

// Optimization 2 (any_of): a load whose base was produced by a load already
// known safe earlier in the same block doesn't need hardening: once the first
// load in the chain retires, every load after it runs on the correct path too.
// A computed value is safe if ANY of its inputs is safe
static cl::opt<bool> SkipDependentLoadsAnyOf(
    "riscv-slh-opt-dependent-anyof",
    cl::desc("Don't harden a load whose address comes from a safe load; a "
             "value is safe when ANY of its inputs is safe (our hardware)"),
    cl::init(false));

// Optimization 2 (all_of): sound-SLH baseline. 
// A computed value is safe only when ALL its inputs are safe. 
static cl::opt<bool> SkipDependentLoadsAllOf(
    "riscv-slh-opt-dependent-allof",
    cl::desc("Sound-SLH variant: don't harden a load whose address comes from "
             "a safe load; a value is safe only when ALL its inputs are safe"),
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
using UnorderedInstrPtrSet = SmallPtrSet<MachineInstr *, 16>;


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

static void clearReg(SparseBitVector<> &SafeRegMap, Register Reg, const TargetRegisterInfo *TRI) {
  SmallVector<unsigned, 4> ToReset;
  for (unsigned R : SafeRegMap) {
    if (TRI->regsOverlap(Register(R), Reg)) { // to solve register aliasing issues and keep consistency
      ToReset.push_back(R);
    }
  }
  for (unsigned R : ToReset)
    SafeRegMap.reset(R);
}

static bool isRegSafe(const SparseBitVector<> &SafeRegMap, Register Reg, const TargetRegisterInfo *TRI) {
  for (unsigned R : SafeRegMap) {
    if (TRI->regsOverlap(Register(R), Reg)) {
      return true;
    }
  }
  return false;
}



//===----------------------------------------------------------------------===//
// Stack (-riscv-slh-opt-stack)
// sp/fp + constant
//===----------------------------------------------------------------------===//

static UnorderedInstrPtrSet findStackLoads(MachineBasicBlock &MBB) {
 
  MachineFunction &MF = *MBB.getParent();
  // x8 ="fp" only when this function actually reserves it as such;
  // otherwise it's just an ordinary callee-saved GPR  sp no ambiguity
  const TargetRegisterInfo *TRI = MF.getSubtarget().getRegisterInfo();
  bool HasFP = MF.getSubtarget<RISCVSubtarget>().getFrameLowering()->hasFP(MF);

  UnorderedInstrPtrSet StackLoads;
  SparseBitVector<> StackRegMap; 

  // sp, fp (if reserved as frame pointer), or a reg holding sp/fp + constant
  auto isStackAddr = [&](Register Reg) {
    return Reg == RISCV::X2 || (HasFP && Reg == RISCV::X8) ||
           isRegSafe(StackRegMap, Reg, TRI);
  };

  for (MachineInstr &MI : MBB) {
    // LOADS
    if (getSafeLoadOpcode(MI.getOpcode())) {
      if (isStackAddr(MI.getOperand(1).getReg()))
        StackLoads.insert(&MI);
      clearReg(StackRegMap, MI.getOperand(0).getReg(), TRI);
      continue;
    }

                           //op 1
    // ADDI (offset > 2047) sp/fp + constant
    bool DefIsStackAddr = MI.getOpcode() == RISCV::ADDI &&
                          MI.getOperand(1).isReg() &&
                          isStackAddr(MI.getOperand(1).getReg());
    // NOT LOADS - maybe more dest
    for (const MachineOperand &MO : MI.operands()) {
      if (MO.isReg() && MO.isDef() && MO.getReg().isPhysical()) {
        clearReg(StackRegMap, MO.getReg(), TRI);
      }
    }
    if (DefIsStackAddr)
      StackRegMap.set(MI.getOperand(0).getReg().id());
  }
  return StackLoads;
}

//===----------------------------------------------------------------------===//
// Dependent (-riscv-slh-opt-dependent-anyof / -allof)
// + stack with -riscv-slh-opt-stack 
//===----------------------------------------------------------------------===//

// anyof - my hardware - one safe input is enough
// allof - sound-SLH baseline
static UnorderedInstrPtrSet selectLoadsDependent(MachineBasicBlock &MBB,
                                                 const UnorderedInstrPtrSet &StackLoads) {
  // Reset per block
  UnorderedInstrPtrSet LoadsToHarden;
  SparseBitVector<> SafeRegMap;
  
  const TargetRegisterInfo *TRI = MBB.getParent()->getSubtarget().getRegisterInfo();

  for (MachineInstr &MI : MBB) {
    // LOADS
    if (getSafeLoadOpcode(MI.getOpcode())) {
      Register Dst = MI.getOperand(0).getReg();
      Register Base = MI.getOperand(1).getReg();

      bool IsDependent = isRegSafe(SafeRegMap, Base, TRI);
      clearReg(SafeRegMap, Dst, TRI);
      if (!(IsDependent || StackLoads.contains(&MI))) {
        //not safe by dependency or stack
        LoadsToHarden.insert(&MI);
        // from now dest is safe bc this ld is safe_ld
        SafeRegMap.set(Dst.id());
      } else if (IsDependent) {
        // stack destination is not safe, only dependent destination is safe
        SafeRegMap.set(Dst.id());
      }
      continue;
    }

    // NOT LOADS
    // v 1.1 and v1 after call
    if (MI.isCall())
      SafeRegMap.clear();


    // a call never makes its defs safe: SafeRegMap was just cleared above
    auto IsSafeUse = [&](const MachineOperand &MO) {
      return MO.isReg() && MO.isUse() && MO.getReg().isPhysical() &&
             isRegSafe(SafeRegMap, MO.getReg(), TRI);
    };
    auto IsRegUse = [&](const MachineOperand &MO) {
      return MO.isReg() && MO.isUse() && MO.getReg().isPhysical();
    };
    bool DefIsSafe;
    if (SkipDependentLoadsAnyOf)
      // any_of: one safe input is enough
      DefIsSafe = llvm::any_of(MI.operands(), IsSafeUse);
    else if (SkipDependentLoadsAllOf)
      // all_of: must read at least one register, and every read register safe
      DefIsSafe = llvm::any_of(MI.operands(), IsRegUse) &&
                  llvm::all_of(MI.operands(), [&](const MachineOperand &MO) {
                    return !IsRegUse(MO) || IsSafeUse(MO);
                  });
    else
      llvm_unreachable("selectLoadsDependent requires a dependent flag");

    // not in slh
    for (const MachineOperand &MO : MI.operands()) {
      //- WRITES to a register
      //es add a0, a1, a2 — a0 is being written, a1 and a2 are being read
      if (MO.isReg() && MO.isDef() && MO.getReg().isPhysical()) {
        //  RISC-V never writes part of a register so registers overlapping np
        // (x regs have no sub-registers, a 32-bit FP write NaN-boxes all 64 bits)
        if (DefIsSafe)
          SafeRegMap.set(MO.getReg().id());
        else
          clearReg(SafeRegMap, MO.getReg(), TRI);
      }
    }
  }
  return LoadsToHarden;
}

//===----------------------------------------------------------------------===//
// Naive (-riscv-slh)
// with -riscv-slh-opt-stack: stack optimization alone
//===----------------------------------------------------------------------===//

static UnorderedInstrPtrSet selectLoadsNaive(MachineBasicBlock &MBB,
                 const UnorderedInstrPtrSet &StackLoads) {
  UnorderedInstrPtrSet LoadsToHarden;
  for (MachineInstr &MI : MBB) {
    if (getSafeLoadOpcode(MI.getOpcode()) && !StackLoads.contains(&MI)) {
      LoadsToHarden.insert(&MI);
    }
  }
  return LoadsToHarden;
}


//===----------------------------------------------------------------------===//
// Hardening loop
//===----------------------------------------------------------------------===//

using LoadSelector = function_ref<UnorderedInstrPtrSet( MachineBasicBlock &, const UnorderedInstrPtrSet &)>;
// for every block, ask the mode which loads to harden and swap them
static bool hardenLoads(MachineFunction &MF, LoadSelector SelectLoadsToHarden) {
  const RISCVInstrInfo *TII = MF.getSubtarget<RISCVSubtarget>().getInstrInfo();

  bool MadeChange = false;
  for (MachineBasicBlock &MBB : MF) {
    UnorderedInstrPtrSet StackLoads;
    if (SkipStackConstLoads)
      StackLoads = findStackLoads(MBB); // if not, empty
    for (MachineInstr *MI : SelectLoadsToHarden(MBB, StackLoads)) {
      //replace with
      MI->setDesc(TII->get(getSafeLoadOpcode(MI->getOpcode())));
       // get the instruction corresponding to this opcode from the
              // from the build time TableGen lookup table (.td)
      MadeChange = true;
    }
  }
  return MadeChange;
}


//===----------------------------------------------------------------------===//
// Entry point
//===----------------------------------------------------------------------===//
//   -riscv-slh                                   naive: every load
//   -riscv-slh -riscv-slh-opt-stack              stack
//   -riscv-slh -riscv-slh-opt-dependent-anyof    dependent (any_of, our hardware)
//   -riscv-slh -riscv-slh-opt-dependent-allof    sound-SLH baseline (all_of)
//===----------------------------------------------------------------------===//
//   -riscv-slh-opt-stack can be added to either dependent variant.
//   At most one of -opt-dependent / -opt-dependent-allof.
//===----------------------------------------------------------------------===//

// inherited predifined function, main of the pass
bool RISCVSafeLoad::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableSafeLoad)
    return false;
  if (SkipDependentLoadsAnyOf && SkipDependentLoadsAllOf)
    reportFatalUsageError("-riscv-slh: use at most one of "
                          "-riscv-slh-opt-dependent-anyof, "
                          "-riscv-slh-opt-dependent-allof");
  if (SkipDependentLoadsAnyOf || SkipDependentLoadsAllOf)
    return hardenLoads(MF, selectLoadsDependent);  return hardenLoads(MF, selectLoadsNaive);
}
