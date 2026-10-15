#include "RISCV.h"
#include "RISCVInstrInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SparseBitVector.h"
#include "llvm/ADT/bit.h"
#include "llvm/CodeGen/LivePhysRegs.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/ReachingDefAnalysis.h"
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

// Optimization 2: a load whose base register was itself produced
// by a load already known safe earlier in the same basic block doesn't need
// hardening: once the first load in the chain has retired, every load after
// it in the chain runs on the correct path too
static cl::opt<bool> SkipDependentLoads(
    "riscv-slh-opt-dependent",
    cl::desc("Don't harden a load whose address comes from another load "
             "already known safe earlier in the same basic block"),
    cl::init(false));

// Optimization 3: per block, harden only as many loads as needed so that
// every instruction that could leak a loaded value waits for a safe_ld 
// minimum number of hardened loads per block, among equally small answers, the deepest
static cl::opt<bool> AggressiveLoads(
    "riscv-slh-opt-aggressive",
    cl::desc("Per basic block, harden the fewest loads such that every "
             "instruction that could leak a loaded value waits for a safe load "),
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

static bool isStore(unsigned Opcode) {
  switch (Opcode) {
  case RISCV::SB:  case RISCV::SH:  case RISCV::SW:  case RISCV::SD:
  case RISCV::FSH: case RISCV::FSW: case RISCV::FSD:
    return true;
  default:
    return false;
  }
}

// DIV/sqrt have operand-dependent latency — SLH isDataInvariant() (X86InstrInfo.cpp)
static bool isDivOrSqrt(unsigned Opcode) {
  switch (Opcode) {
  case RISCV::DIV:  case RISCV::DIVU:  case RISCV::REM:  case RISCV::REMU:
  case RISCV::DIVW: case RISCV::DIVUW: case RISCV::REMW: case RISCV::REMUW:
  case RISCV::FDIV_H: case RISCV::FDIV_S: case RISCV::FDIV_D:
  case RISCV::FSQRT_H: case RISCV::FSQRT_S: case RISCV::FSQRT_D:
    return true;
  default:
    return false;
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


namespace {
// empty set = value is trusted/ nothing to harden in this bb 
using OrderedInstrPtrSet = SmallSetVector<MachineInstr *, 4>;

class AggressiveSelector {
  MachineBasicBlock &MBB;
  const ReachingDefInfo &RDI;
  const UnorderedInstrPtrSet &StackLoads; // if opt-stack, if not it's empty
  DenseMap<const MachineInstr *, unsigned> InstrIndex; // index of each instruction in the block
  SmallVector<unsigned, 4> CallIndexes;          // indexes of the calls

  DenseMap<MachineInstr *, OrderedInstrPtrSet> LoadHistoryCache; 
  SmallVector<OrderedInstrPtrSet, 16> CandidateLoadsPerUnsafeUse; // one set of loads per unsafe use

public:
  AggressiveSelector(MachineBasicBlock &MBB, const ReachingDefInfo &RDI,
    const UnorderedInstrPtrSet &StackLoads) : MBB(MBB), RDI(RDI), StackLoads(StackLoads) {
    unsigned I = 0;
    for (MachineInstr &MI : instructionsWithoutDebug(MBB.instr_begin(), MBB.instr_end())) {
      if (MI.isCall())
        CallIndexes.push_back(I);
      InstrIndex[&MI] = I++;
    }
  }

  UnorderedInstrPtrSet selectLoads() {
    UnorderedInstrPtrSet LoadsToHarden;
    collectCandidateLoadsPerUnsafeUse();
    pickMinimum(LoadsToHarden);

    assert(llvm::all_of(CandidateLoadsPerUnsafeUse, [&](const OrderedInstrPtrSet &UnsafeUse) {
             return hasLoadToHarden(UnsafeUse, LoadsToHarden);
           }) && "every unsafe use must have a hardened load");
    return LoadsToHarden;
  }

private:
 
  static bool hasLoadToHarden(const OrderedInstrPtrSet &UnsafeUse,
                        const SmallPtrSetImpl<MachineInstr *> &LoadsToHarden) {
    return llvm::any_of(UnsafeUse, [&](MachineInstr *Load) { return LoadsToHarden.contains(Load); });
  }

  bool callBetween(const MachineInstr *Def, const MachineInstr *Use) const {
    unsigned D = InstrIndex.lookup(Def), U = InstrIndex.lookup(Use);
    return llvm::any_of(CallIndexes, [&](unsigned C) { return D < C && C < U; });
  }

  //returns the entire load hsitory of this reg in this BB [l1, l2, l3]
  OrderedInstrPtrSet getLoadHistoryOfUse(MachineInstr *MI, Register Reg) {
    // live-in or x0 (= always 0): there is nothing to harden to make them safe
    if (Reg == RISCV::X0 || !RDI.hasLocalDefBefore(MI, Reg))
      return {};
      // load is unique bc we are in the same basic block
      // if it's not unique = comes form different block = live in handled above 
    MachineInstr *LastWriter = RDI.getUniqueReachingMIDef(MI, Reg);
    assert(LastWriter && "expected one write of Reg before MI in this block");
    OrderedInstrPtrSet Loads = getLoadHistoryOfDef(LastWriter);
    if (!callBetween(LastWriter, MI))
      return Loads;
    
    // a call splits a block: I treat values from before the call as live-outs
    // (harden a load behind them here). I can guarantee that those specific values
    // are not speculative, but using that one value doesn't guarantee that the
    // instruction's other inputs (from after the call) aren't speculative anymore
    addUnsafeUse(Loads);
    return {}; // nothing needs hardening bc it's before the call anyways, 
              //no history, can't harden something before the call to guarantee safety
  }

  OrderedInstrPtrSet getLoadHistoryOfAllUses(MachineInstr *MI) {
    OrderedInstrPtrSet Loads;
    for (const MachineOperand &MO : MI->operands()) {
      if (MO.isReg() && MO.isUse() && !MO.isUndef() && MO.getReg().isPhysical()) {
        OrderedInstrPtrSet In = getLoadHistoryOfUse(MI, MO.getReg());
        Loads.insert(In.begin(), In.end()); // make one single big list for all operands
        //ex add a4, a1, a2 (l1, l2)
      }
    }
    return Loads;
  }

  OrderedInstrPtrSet getLoadHistoryOfDef(MachineInstr *LastWriter) {
    // one cache entry:  It->first = add a4, a2, a1   (the instruction)
    //                   It->second = {ld1, ld2}      (load history of all operands)
    auto It = LoadHistoryCache.find(LastWriter);
    if (It != LoadHistoryCache.end())
      return It->second;
    
    // i don't have the last writer's history yet, first time its product is used   
    OrderedInstrPtrSet Loads;
    if (getSafeLoadOpcode(LastWriter->getOpcode())) {
      Register LoadBase = LastWriter->getOperand(1).getReg();
      // opt-stack: stays plain, what the stack holds is trusted
      if (!StackLoads.contains(LastWriter)) {
        Loads = getLoadHistoryOfUse(LastWriter, LoadBase);
        Loads.insert(LastWriter);
      }
    } else if (!LastWriter->isCall() && !LastWriter->mayLoadOrStore() &&
               !LastWriter->hasUnmodeledSideEffects()) {
      Loads = getLoadHistoryOfAllUses(LastWriter); // arithmetic: carries its inputs
    }
 
    LoadHistoryCache[LastWriter] = Loads;
    return Loads;
  }

 
  void addUnsafeUse(OrderedInstrPtrSet Loads) {
    if (!Loads.empty())
      CandidateLoadsPerUnsafeUse.push_back(std::move(Loads));
  }

  void collectCandidateLoadsPerUnsafeUse() {

  //1-BLOCK INSTRUCTIONS
    for (MachineInstr &MI : instructionsWithoutDebug(MBB.instr_begin(), MBB.instr_end())) {
      if (getSafeLoadOpcode(MI.getOpcode()) || isStore(MI.getOpcode())) {
        addUnsafeUse(getLoadHistoryOfUse(&MI, MI.getOperand(1).getReg()));   // address
        // no speculative value may be stored, or a plain stack load would read it back as trusted
        // writing to stack and then reading again would be a way to avoid my hardening
        if (SkipStackConstLoads && isStore(MI.getOpcode()))
          addUnsafeUse(getLoadHistoryOfUse(&MI, MI.getOperand(0).getReg()));   // data
      } else if (MI.isConditionalBranch() || isDivOrSqrt(MI.getOpcode())) {
        addUnsafeUse(getLoadHistoryOfAllUses(&MI));
      } else if (MI.isCall() || MI.isReturn() || MI.isIndirectBranch() || MI.hasUnmodeledSideEffects()) {
       // Separate, not merged, because these instructions don't wait for all their inputs together
       // having jsut 1 operand safe is not enough
        for (const MachineOperand &MO : MI.operands()) {
          if (MO.isReg() && MO.isUse() && !MO.isUndef() && MO.getReg().isPhysical()) {
            addUnsafeUse(getLoadHistoryOfUse(&MI, MO.getReg()));
          }
        }
      }
    }

  //2-LIVE OUTs 
    // values a later block reads (also epilogue restores, including ra: for a
    // return block LivePhysRegs adds the saved/restored registers, ra among them,
    // even though the RISC-V ABI lists ra as caller-saved)
    MachineFunction &MF = *MBB.getParent();
    // liveliness always ON for RISC-V 
    assert(MF.getRegInfo().tracksLiveness() && "live-out check needs liveness");
    LivePhysRegs LiveOut(*MF.getSubtarget().getRegisterInfo());  
    LiveOut.addLiveOuts(MBB);                                     
    SmallPtrSet<MachineInstr *, 8> Seen;
    for (MCPhysReg R : LiveOut) {
      if (MachineInstr *LastWriter = RDI.getLocalLiveOutMIDef(&MBB, R)) {
        if (Seen.insert(LastWriter).second) {
          addUnsafeUse(getLoadHistoryOfDef(LastWriter));
        }
      }
    }
  }

    
  // minimum hitting set: the fewest loads such that every unsafe use has one
  // of its loads hardened (among equally few, the deepest)
  void pickMinimum(SmallPtrSetImpl<MachineInstr *> &LoadsToHarden) const {

    // 1 - FORCED PICKS
    // a load that is the only candidate of some unsafe use is a must
    for (const OrderedInstrPtrSet &UseLoads : CandidateLoadsPerUnsafeUse) {
      if (UseLoads.size() == 1) {
        LoadsToHarden.insert(UseLoads.front());
      }
    }

    // 2 - MINIMUM HITTING SET     
    SmallVector<const OrderedInstrPtrSet *, 16> Uncovered;
    SmallSetVector<MachineInstr *, 16> Candidates;
    for (const OrderedInstrPtrSet &UseLoads : CandidateLoadsPerUnsafeUse) {
      if (!hasLoadToHarden(UseLoads, LoadsToHarden)) {
        Uncovered.push_back(&UseLoads);
        Candidates.insert(UseLoads.begin(), UseLoads.end());
      }
    }
    unsigned NumCandidates = Candidates.size();
    // so i can see if it's a real problem now that im just testing
    assert(NumCandidates < 32 && "too many candidate loads for this prototype");

    //  each uncovered use as a bitmask: bit i set = candidate i is in it
    SmallVector<uint32_t, 16> UnsafeUsesMasks;
    for (const OrderedInstrPtrSet *UseLoads : Uncovered) {
      uint32_t Mask = 0;
      //   I                         0     1     2
      //   Candidates total set : [ ld1 | ld2 | ld3 ]
      //   use {ld1, ld3}:
      //     I = 0  ld1 ? yes  ->  0 0 1
      //     I = 1  ld2 ? no   ->  0 0 1
      //     I = 2  ld3 ? yes  ->  1 0 1
      for (unsigned I = 0; I < NumCandidates; ++I) {
        if (UseLoads->contains(Candidates[I])) {
          Mask |= 1u << I;
        }
      }
      UnsafeUsesMasks.push_back(Mask);
    }

    // combinations of candidates by incrementing group size
    // The first size where some combination hits every use is the minimum: 
    // keep the deepest of that size groups (loads latest in the
    // block = highest sum of instruction indexes) 
    uint32_t Best = 0;
    for (unsigned GroupSize = 1; GroupSize <= NumCandidates && !Best; ++GroupSize) {
      unsigned BestDepth = 0;
      for (uint32_t Group = (1u << GroupSize) - 1; Group < (1u << NumCandidates);) {
        // a use is covered if it and the group share 1-bit
        //   use {ld1,ld2}:  0 1 1
        //   group {ld1}:    0 0 1
        //                       ^ both 1 -> covered
        //   use {ld1,ld3}:  1 0 1
        //   group {ld1}:    0 0 1
        //                       ^ both 1 -> covered

        // if all uses covered by this group
        if (llvm::all_of(UnsafeUsesMasks, [&](uint32_t Mask) { return Mask & Group; })) {
          unsigned Depth = 0;
          for (unsigned I = 0; I < NumCandidates; ++I) {
            if (Group & (1u << I)) {
              Depth += InstrIndex.lookup(Candidates[I]);
            }
          }
          if (!Best || Depth > BestDepth) {
            Best = Group;
            BestDepth = Depth;
          }
        }
        // next number with the same ammount of 1-bits = another combo of the same size
        //Gosper's hack (it's the increment of the for loop)
        uint32_t Low = Group & -Group, Up = Group + Low;
        Group = (((Up ^ Group) >> 2) / Low) | Up;
      }
    }
    for (unsigned I = 0; I < NumCandidates; ++I) {
      if (Best & (1u << I)) {
        LoadsToHarden.insert(Candidates[I]);
      }
    }
  }
};
} 

//===----------------------------------------------------------------------===//
// Aggressive (-riscv-slh-opt-aggressive)
// + stack with -riscv-slh-opt-stack 
//===----------------------------------------------------------------------===//

static UnorderedInstrPtrSet selectLoadsAggressive(MachineBasicBlock &MBB, const ReachingDefInfo &RDI,
                      const UnorderedInstrPtrSet &StackLoads) {
  return AggressiveSelector(MBB, RDI, StackLoads).selectLoads();
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
// Dependent (-riscv-slh-opt-dependent)
// + stack with -riscv-slh-opt-stack 
//===----------------------------------------------------------------------===//

static UnorderedInstrPtrSet selectLoadsDependent(MachineBasicBlock &MBB, const UnorderedInstrPtrSet &StackLoads) {
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
    //any_of even just one is enough
    bool DefIsSafe = llvm::any_of(MI.operands(), [&](const MachineOperand &MO) {
                                            //MI reads this reg
                        return MO.isReg() && MO.isUse() && MO.getReg().isPhysical() &&
                              isRegSafe(SafeRegMap, MO.getReg(), TRI);
                      });

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
//   -riscv-slh -riscv-slh-opt-dependent          dependent
//   -riscv-slh -riscv-slh-opt-aggressive         aggressive, fewest loads
//===----------------------------------------------------------------------===//
//   -riscv-slh-opt-stack can be added to dependent and to aggressive.
//   At most one of dependent / aggressive 
//===----------------------------------------------------------------------===//

// inherited predifined function, main of the pass
bool RISCVSafeLoad::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableSafeLoad) return false;
  if (SkipDependentLoads && AggressiveLoads)
    reportFatalUsageError("-riscv-slh: use at most one of "
                          "-riscv-slh-opt-dependent, "
                          "-riscv-slh-opt-aggressive");
  if (AggressiveLoads) {
    ReachingDefInfo RDI; // RDA
    RDI.run(MF);
    return hardenLoads(
        MF, [&](MachineBasicBlock &MBB,
                const UnorderedInstrPtrSet &StackLoads) {
          return selectLoadsAggressive(MBB, RDI, StackLoads);
        });
  }
  if (SkipDependentLoads)
    return hardenLoads(MF, selectLoadsDependent);
  return hardenLoads(MF, selectLoadsNaive);
}
