#ifndef EGALITO_ANALYSIS_JUMP_TABLE_H
#define EGALITO_ANALYSIS_JUMP_TABLE_H

#include "chunk/concrete.h"

class SearchState;
class SlicingSearch;
class TreeNode;

class JumpTableSearch {
private:
    TreeNode *indexExpr;
public:
    void search(Module *module);
    void search(Function *function);
private:
    bool matchJumpTable(SearchState *state);
    bool matchJumpTableBounds(SlicingSearch *search);
    bool boundsHelper(SlicingSearch *search, SearchState *state);
};

#endif
