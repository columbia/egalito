#ifndef EGALITO_DISASM_MAKE_SEMANTIC_H
#define EGALITO_DISASM_MAKE_SEMANTIC_H

#include <capstone/capstone.h>

class Instruction;
class InstructionSemantic;

class MakeSemantic {
public:
    static InstructionSemantic *makeNormalSemantic(
        Instruction *instruction, cs_insn *insn);
};

#endif
