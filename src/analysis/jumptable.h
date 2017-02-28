#ifndef EGALITO_ANALYSIS_JUMP_TABLE_H
#define EGALITO_ANALYSIS_JUMP_TABLE_H

#include <vector>
#include <climits>
#include "chunk/concrete.h"
#include "types.h"

class SearchState;
class SlicingSearch;
class TreeNode;

class JumpTableDescriptor {
private:
    Function *function;
    Instruction *instruction;
    address_t address;
    TreeNode *indexExpr;
    Register indexRegister;
    int scale;
    long bound;
public:
    JumpTableDescriptor(Function *function, Instruction *instruction)
        : function(function), instruction(instruction),
        address(0), indexExpr(nullptr), indexRegister(INVALID_REGISTER),
        scale(1), bound(LONG_MAX) {}

    Function *getFunction() const { return function; }
    Instruction *getInstruction() const { return instruction; }
    address_t getAddress() const { return address; }
    TreeNode *getIndexExpr() const { return indexExpr; }
    Register getIndexRegister() const { return indexRegister; }
    int getScale() const { return scale; }
    long getBound() const { return bound; }
    bool isBoundKnown() const { return bound != LONG_MAX; }
    long getEntries() const;

    void setAddress(address_t address) { this->address = address; }
    void setIndexExpr(TreeNode *node) { indexExpr = node; }
    void setIndexRegister(Register r) { indexRegister = r; }
    void setScale(int scale) { this->scale = scale; }
    void setBound(long bound) { this->bound = bound; }
};

class JumpTableSearch {
private:
    bool savePartialInfoTables;
    std::vector<JumpTableDescriptor *> tableList;
public:
    JumpTableSearch(bool savePartialInfoTables = true)
        : savePartialInfoTables(savePartialInfoTables) {}

    void search(Module *module);
    void search(Function *function);

    const std::vector<JumpTableDescriptor *> &getTableList() const
        { return tableList; }
private:
    bool matchJumpTable(SearchState *state, JumpTableDescriptor *d);
    bool matchJumpTableBounds(SlicingSearch *search, JumpTableDescriptor *d);
};

#endif
