#ifndef EGALITO_ANALYSIS_SLICING_H
#define EGALITO_ANALYSIS_SLICING_H

#include <vector>
#include <map>
#include "controlflow.h"
#include "chunk/instruction.h"

class TreeNode;

class SearchState {
private:
    ControlFlowNode *node;
    Instruction *instruction;
    std::vector<bool> regs;
    std::vector<SearchState *> parents;
    std::map<int, TreeNode *> regTree;
    bool jumpTaken;
public:
    SearchState() : node(nullptr), instruction(nullptr), jumpTaken(false) {}
    SearchState(ControlFlowNode *node, Instruction *instruction)
        : node(node), instruction(instruction), regs(X86_REG_ENDING), jumpTaken(false) {}
    SearchState(const SearchState &other)
        : node(other.node), instruction(other.instruction), regs(other.regs), jumpTaken(other.jumpTaken) {}

    ControlFlowNode *getNode() const { return node; }
    Instruction *getInstruction() const { return instruction; }
    void setNode(ControlFlowNode *node) { this->node = node; }
    void setInstruction(Instruction *instruction)
        { this->instruction = instruction; }

    const std::vector<bool> &getRegs() const { return regs; }
    void addReg(int reg) { regs[reg] = true; }
    void removeReg(int reg) { regs[reg] = false; }
    bool getReg(int reg) { return regs[reg]; }

    void addParent(SearchState *parent) { parents.push_back(parent); }
    const std::vector<SearchState *> &getParents() const { return parents; }

    TreeNode *getRegTree(int reg);
    void setRegTree(int reg, TreeNode *tree);

    void setJumpTaken(bool to) { jumpTaken = to; }
    bool getJumpTaken() const { return jumpTaken; }
};

class SlicingUtilities {
public:
    const char *printReg(int reg);
    void printRegs(SearchState *state, bool withNewline = true);
    void printRegTrees(SearchState *state);
    void copyParentRegTrees(SearchState *state);
    TreeNode *makeMemTree(SearchState *state, x86_op_mem *mem);
    TreeNode *getParentRegTree(SearchState *state, int reg);
};

class SlicingSearch {
private:
    ControlFlowGraph *cfg;
    std::vector<SearchState *> stateList;  // history of states
    std::vector<SearchState *> conditions;  // conditional jumps
public:
    SlicingSearch(ControlFlowGraph *cfg) : cfg(cfg) {}

    /** Run search beginning at this instruction. */
    void sliceAt(Instruction *i);

    SearchState *getInitialState() const { return stateList.front(); }
    const std::vector<SearchState *> &getConditionList() const
        { return conditions; }
private:
    void buildStatePass(SearchState *startState);
    void buildRegTreePass();

    void debugPrintRegAccesses(Instruction *i);
    bool isKnownInstruction(unsigned id);
    void buildStateFor(SearchState *state);
    void buildRegTreesFor(SearchState *state);
    void detectInstruction(SearchState *state, bool makeTrees);
    void detectJumpRegTrees(SearchState *state, bool makeTrees);
};

#endif
