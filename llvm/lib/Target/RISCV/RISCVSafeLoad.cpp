#include "RISCV.h"
#include "RISCVInstrInfo.h"
#include "RISCVSubtarget.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

//FLAG to enable naive
static cl::opt<bool> EnableSafeLoad(
    "riscv-slh-naive",
    cl::desc("Replace all integer loads with safe-load variants (SLH hardening)"),
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

// inherited predifined function, main of the pass            
bool RISCVSafeLoad::runOnMachineFunction(MachineFunction &MF) {
  if (!EnableSafeLoad)
    return false;

  const RISCVInstrInfo *TII =
      MF.getSubtarget<RISCVSubtarget>().getInstrInfo();

  bool MadeChange = false;
  for (MachineBasicBlock &MBB : MF) {
    for (MachineInstr &MI : MBB) {
      unsigned SafeOpc = getSafeLoadOpcode(MI.getOpcode());
      if (!SafeOpc)
        continue;
      //substitute with:
      MI.setDesc(TII->get(SafeOpc));
                // get the instruction corresponding to this opcode from the         
                // from the build time TableGen lookup table (.td)
      MadeChange = true;
    }
  }
  return MadeChange;
}
