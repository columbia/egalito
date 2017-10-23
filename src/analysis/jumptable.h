#ifndef EGALITO_ANALYSIS_JUMP_TABLE_H
#define EGALITO_ANALYSIS_JUMP_TABLE_H

#include <vector>
#include <climits>
#include "chunk/concrete.h"
#include "instr/register.h"
#include "types.h"

class SearchState;
class SlicingSearch;
class TreeNode;

/** Represents a single jump table as identified from program slicing (from
    indirect jumps). Tables are deduplicated later, so there could be multiple
    descriptors which use the same jump table data.
*/
class JumpTableDescriptor {
private:
    Function *function;
    Instruction *instruction;  // indirect jump to this jump table
    address_t address;
    address_t targetBaseAddress;
    TreeNode *indexExpr;
    Register indexRegister;
    int scale;
    long bound;
public:
    JumpTableDescriptor(Function *function, Instruction *instruction)
        : function(function), instruction(instruction),
        address(0), targetBaseAddress(0), indexExpr(nullptr),
        indexRegister(INVALID_REGISTER), scale(1), bound(LONG_MAX) {}

    Function *getFunction() const { return function; }
    Instruction *getInstruction() const { return instruction; }
    address_t getAddress() const { return address; }
    address_t getTargetBaseAddress() const { return targetBaseAddress; }
    TreeNode *getIndexExpr() const { return indexExpr; }
    Register getIndexRegister() const { return indexRegister; }
    int getScale() const { return scale; }
    long getBound() const { return bound; }
    bool isBoundKnown() const { return bound != LONG_MAX; }
    long getEntries() const;

    void setAddress(address_t a) { address = a; }
    void setTargetBaseAddress(address_t a) { targetBaseAddress = a; }
    void setIndexExpr(TreeNode *node) { indexExpr = node; }
    void setIndexRegister(Register r) { indexRegister = r; }
    void setScale(int scale) { this->scale = scale; }
    void setBound(long bound) { this->bound = bound; }
    void setEntries(long entries) { this->bound = entries - 1; }
};

class JumpTableSearch {
private:
    bool savePartialInfoTables;
    std::vector<JumpTableDescriptor *> tableList;
    std::vector<Instruction *> possibleMissList;
public:
    JumpTableSearch(bool savePartialInfoTables = true)
        : savePartialInfoTables(savePartialInfoTables) {}

    void search(Module *module);
    void search(Function *function);

    const std::vector<JumpTableDescriptor *> &getTableList() const
        { return tableList; }
    const std::vector<Instruction *> &getPossibleMissList() const
        { return possibleMissList; }
    void clearPossibleMissList() { possibleMissList.clear(); }

private:
    bool matchJumpTable(SearchState *state, JumpTableDescriptor *d);
    bool matchJumpTableBounds(SlicingSearch *search, JumpTableDescriptor *d);
    std::vector<address_t> getTableAddresses(SearchState *state, TreeNode *tree);
};

#endif
