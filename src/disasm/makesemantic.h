#ifndef EGALITO_DISASM_MAKE_SEMANTIC_H
#define EGALITO_DISASM_MAKE_SEMANTIC_H

#include <capstone/capstone.h>

class Instruction;
class InstructionSemantic;

class MakeSemantic {
public:
    static InstructionSemantic *makeNormalSemantic(
        Instruction *instruction, cs_insn *ins);

    static bool isRIPRelative(cs_insn *ins, int opIndex);
    static int determineDisplacementSize(cs_insn *ins);
    static int getDispOffset(cs_insn *ins);
    static int getDispOffset(cs_insn *ins, int opIndex);
};

#endif
