//===----------------------------------------------------------------------===//
// Integer safe-load instructions: custom-2 opcode (0x5b)
//   funct3: 000=safe_lb 001=safe_lh 010=safe_lw 011=safe_ld
//           100=safe_lbu 101=safe_lhu 110=safe_lwu
//
// FP safe-load instructions: custom-3 opcode (0x7b)
//   funct3: 010=safe_flw  011=safe_fld
//===----------------------------------------------------------------------===//


//ri=register immidiate 

let hasSideEffects = 0, mayLoad = 1, mayStore = 0 in
class SafeLoad_ri<bits<3> funct3, string opcodestr, DAGOperand rty = GPR>
    : RVInstI<funct3, OPC_CUSTOM_2, (outs rty:$rd),
              (ins BasePtr:$rs1, simm12_lo_optional:$imm12),
              opcodestr, "$rd, ${imm12}(${rs1})">;

let hasSideEffects = 0, mayLoad = 1, mayStore = 0 in
class SafeFPLoad_ri<bits<3> funct3, string opcodestr, DAGOperand rty>
    : RVInstI<funct3, OPC_CUSTOM_3, (outs rty:$rd),
              (ins BasePtr:$rs1, simm12_lo_optional:$imm12),
              opcodestr, "$rd, ${imm12}(${rs1})">;

// RV32I + RV64I integer safe loads
let IsSignExtendingOpW = 1 in {
def SAFE_LB  : SafeLoad_ri<0b000, "safe_lb">,  Sched<[WriteLDB, ReadMemBase]>;
def SAFE_LH  : SafeLoad_ri<0b001, "safe_lh">,  Sched<[WriteLDH, ReadMemBase]>;
def SAFE_LW  : SafeLoad_ri<0b010, "safe_lw">,  Sched<[WriteLDW, ReadMemBase]>;
}
def SAFE_LBU : SafeLoad_ri<0b100, "safe_lbu">, Sched<[WriteLDB, ReadMemBase]>;
def SAFE_LHU : SafeLoad_ri<0b101, "safe_lhu">, Sched<[WriteLDH, ReadMemBase]>;

// RV64I only integer safe loads
let Predicates = [IsRV64] in {
def SAFE_LWU : SafeLoad_ri<0b110, "safe_lwu">, Sched<[WriteLDW, ReadMemBase]>;
def SAFE_LD  : SafeLoad_ri<0b011, "safe_ld">,  Sched<[WriteLDD, ReadMemBase]>;
}

// FP safe loads (custom-3, 0x7b)
let Predicates = [HasStdExtF] in
def SAFE_FLW : SafeFPLoad_ri<0b010, "safe_flw", FPR32>, Sched<[WriteFLD32, ReadMemBase]>;
let Predicates = [HasStdExtD] in
def SAFE_FLD : SafeFPLoad_ri<0b011, "safe_fld", FPR64>, Sched<[WriteFLD64, ReadMemBase]>;
