#ifndef EGALITO_ANALYSIS_JUMP_TABLE_H
#define EGALITO_ANALYSIS_JUMP_TABLE_H

#include "chunk/concrete.h"

class ControlFlowGraph;
class IndirectJumpInstruction;

class JumpTableSearch {
public:
    void search(Module *module);
    void search(Function *function);
};

#endif
