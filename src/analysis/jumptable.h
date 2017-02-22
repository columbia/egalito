#ifndef EGALITO_ANALYSIS_JUMP_TABLE_H
#define EGALITO_ANALYSIS_JUMP_TABLE_H

#include "chunk/concrete.h"

class SearchState;

class JumpTableSearch {
public:
    void search(Module *module);
    void search(Function *function);
private:
    void matchJumpTable(SearchState *state);
};

#endif
