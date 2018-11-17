#ifndef EGALITO_DISASM_MAKE_SEMANTIC_H
#define EGALITO_DISASM_MAKE_SEMANTIC_H

#include <capstone/capstone.h>
#include "riscv-disas.h"

class Instruction;
class InstructionSemantic;
class Assembly;

class MakeSemantic {
public:
    static InstructionSemantic *makeNormalSemantic(
        Instruction *instruction, cs_insn *ins);
#ifdef ARCH_RISCV
    static InstructionSemantic *makeNormalSemantic(
        Instruction *instruction, rv_instr *ins);
#endif

    static bool isRIPRelative(Assembly *assembly, int opIndex);
    static int determineDisplacementSize(Assembly *assembly, int opIndex);
    static int getDispOffset(Assembly *assembly, int opIndex);
    static int getOpIndex(Assembly *assembly, size_t offset);
};

#endif
