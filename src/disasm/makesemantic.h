#ifndef EGALITO_DISASM_MAKE_SEMANTIC_H
#define EGALITO_DISASM_MAKE_SEMANTIC_H

#include <capstone/capstone.h>
#include <disasm/assembly.h>

class Instruction;
class InstructionSemantic;

class MakeSemantic {
public:
    static InstructionSemantic *makeNormalSemantic(
        Instruction *instruction, cs_insn *ins);

    static bool isRIPRelative(Assembly *assembly, int opIndex);
    static int determineDisplacementSize(Assembly *assembly);
    static int getDispOffset(Assembly *assembly, int opIndex);
};

#endif
