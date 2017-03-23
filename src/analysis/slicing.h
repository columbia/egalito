#ifndef EGALITO_ANALYSIS_SLICING_H
#define EGALITO_ANALYSIS_SLICING_H

#include <vector>
#include <map>
#include "controlflow.h"
#include "chunk/instruction.h"

class TreeNode;

class SlicingInstructionState;

class SearchState {
private:
    typedef std::pair<TreeNode *, TreeNode *> memTreeType;

    ControlFlowNode *node;
    Instruction *instruction;
    SlicingInstructionState *iState;
    std::vector<bool> regs;
    std::vector<SearchState *> parents;
    std::map<int, TreeNode *> regTree;
    std::vector<memTreeType> memTree;
    bool jumpTaken;
public:
    SearchState() : node(nullptr), instruction(nullptr), iState(nullptr), jumpTaken(false) {}
    SearchState(ControlFlowNode *node, Instruction *instruction)
        : node(node), instruction(instruction), iState(nullptr), regs(REGISTER_ENDING), jumpTaken(false) {}
    SearchState(const SearchState &other)
        : node(other.node), instruction(other.instruction), iState(nullptr), regs(other.regs), jumpTaken(other.jumpTaken) {}

    ControlFlowNode *getNode() const { return node; }
    Instruction *getInstruction() const { return instruction; }
    SlicingInstructionState *getIState() const { return iState; }
    void setNode(ControlFlowNode *node) { this->node = node; }
    void setInstruction(Instruction *instruction)
        { this->instruction = instruction; }
    void setIState(SlicingInstructionState *iState)
        { this->iState = iState; }

    const std::vector<bool> &getRegs() const { return regs; }
    void addReg(int reg) { regs[reg] = true; }
    void removeReg(int reg) { regs[reg] = false; }
    bool getReg(int reg) { return regs[reg]; }

    void addParent(SearchState *parent) { parents.push_back(parent); }
    const std::vector<SearchState *> &getParents() const { return parents; }

    TreeNode *getRegTree(int reg);
    void setRegTree(int reg, TreeNode *tree);

    const std::vector<memTreeType> &getMemTree() const { return memTree; }
    void addMemTree(TreeNode *memTree, TreeNode *regTree);
    void setMemTree(std::vector<memTreeType> memTree) { this->memTree = memTree; }

    void setJumpTaken(bool to) { jumpTaken = to; }
    bool getJumpTaken() const { return jumpTaken; }
};

class SlicingUtilities {
public:
    const char *printReg(int reg);
    void printRegs(SearchState *state, bool withNewline = true);
    void printRegTrees(SearchState *state);
    void printMemTrees(SearchState *state);
    void copyParentRegTrees(SearchState *state);
    void copyParentMemTrees(SearchState *state);
    TreeNode *makeMemTree(SearchState *state, const x86_op_mem *mem);
    TreeNode *makeMemTree(SearchState *state,
                          const arm64_op_mem *mem,
                          arm64_extender ext,
                          arm64_shifter sft_type,
                          unsigned int sft_value);
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
    void buildStateFor(SearchState *state);
    void buildRegTreesFor(SearchState *state);
    void detectInstruction(SearchState *state, bool firstPass);
    void detectJumpRegTrees(SearchState *state, bool firstPass);
};

#endif
