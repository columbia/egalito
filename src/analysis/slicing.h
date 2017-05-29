#ifndef EGALITO_ANALYSIS_SLICING_H
#define EGALITO_ANALYSIS_SLICING_H

#include <vector>
#include <map>
#include <set>
#include "controlflow.h"
#include "flow.h"
#include "instr/register.h"
#include "chunk/chunklist.h"

class Instruction;
class TreeNode;
class Memory;
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
    std::set<int> mems;
    bool jumpTaken;
public:
    SearchState()
        : node(nullptr), instruction(nullptr), iState(nullptr),
          jumpTaken(false) {}
    SearchState(ControlFlowNode *node, Instruction *instruction)
        : node(node), instruction(instruction), iState(nullptr),
          regs(REGISTER_ENDING), jumpTaken(false) {}
    SearchState(const SearchState &other)
        : node(other.node), instruction(other.instruction),
          iState(nullptr), regs(other.regs),
          mems(other.mems), jumpTaken(other.jumpTaken) {}
    virtual ~SearchState();

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

    const std::set<int> &getMems() const { return mems; }
    void addMem(int offset) { mems.insert(offset); }
    void removeMem(int offset) { mems.erase(offset); }
    bool getMem(int offset) { return mems.find(offset) != mems.end(); }
    const std::vector<memTreeType> &getMemTrees() const { return memTree; }
    void addMemTree(TreeNode *memTree, TreeNode *regTree);
    void setMemTree(std::vector<memTreeType> memTree) { this->memTree = memTree; }
    TreeNode *getMemTree() const;

    void setJumpTaken(bool to) { jumpTaken = to; }
    bool getJumpTaken() const { return jumpTaken; }

    virtual void flow(Register reg1, bool overwriteTarget) = 0;
    virtual void flow(Register reg1, Register reg2, bool overwriteTarget) = 0;
    virtual void flow(Register reg1, Register reg2, Register reg3,
                      bool overwriteTarget) = 0;

    virtual void flow(Register reg1, Memory *mem1, bool overwriteTarget) = 0;
    virtual void flow(Memory *mem1, Register reg1, bool overwriteTarget) = 0;
};

template <typename FlowType>
class DirectedSearchState : public SearchState {
public:
    DirectedSearchState() : SearchState() {}
    DirectedSearchState(ControlFlowNode *node, Instruction *instruction)
        : SearchState(node, instruction) {}
    DirectedSearchState(const SearchState &other)
        : SearchState(other) {}

    void flow(Register reg1, bool overwriteTarget) {
        FlowRegElement s(reg1, this);
        FlowType::source(&s, overwriteTarget);
    }
    void flow(Register reg1, Register reg2, bool overwriteTarget) {
        FlowRegElement s(reg1, this);
        FlowRegElement t(reg2, this);
        FlowType::channel(&s, &t, overwriteTarget);
    }
    void flow(Register reg1, Register reg2, Register reg3, bool overwriteTarget) {
        FlowRegElement s1(reg1, this);
        FlowRegElement s2(reg2, this);
        FlowRegElement t(reg3, this);
        FlowType::confluence(&s1, &s2, &t, overwriteTarget);
    }

    void flow(Register reg1, Memory *mem1, bool overwriteTarget) {
        FlowRegElement r(reg1, this);
        FlowMemElement m(mem1, this);
        FlowType::channel(&r, &m, overwriteTarget);
    }
    void flow(Memory *mem1, Register reg1, bool overwriteTarget) {
        FlowRegElement r(reg1, this);
        FlowMemElement m(mem1, this);
        FlowType::channel(&m, &r, overwriteTarget);
    }
};


class SlicingUtilities {
public:
    const char *printReg(int reg);
    void printRegs(SearchState *state, bool withNewline = true);
    void printMems(SearchState *state, bool withNewline = true);
    void printRegTrees(SearchState *state);
    void printMemTrees(SearchState *state);
    void copyParentRegTrees(SearchState *state);
    void copyParentMemTrees(SearchState *state);
    TreeNode *makeMemTree(SearchState *state, const x86_op_mem *mem);
    TreeNode *makeMemTree(SearchState *state,
                          size_t width,
                          const arm64_op_mem *mem,
                          arm64_shifter sft_type,
                          unsigned int sft_value);
    TreeNode *getParentRegTree(SearchState *state, int reg);
};

class SlicingHalt {
public:
    virtual bool cutoff(SearchState *) = 0;
};

class BackwardSlicing {
    typedef DirectedSearchState<BackwardFlow> BackwardSearchState;
public:
    int step() const { return -1; }
    bool isIndexValid(int index, int size) { return (index >= 0); }
    void setParent(SearchState *current, SearchState *next)
        { current->addParent(next); }
    SearchState *makeSearchState(ControlFlowNode *node, Instruction *instruction)
        { return new BackwardSearchState(node, instruction); }
    SearchState *makeSearchState(const SearchState &other)
        { return new BackwardSearchState(other); }
};

class ForwardSlicing {
    typedef DirectedSearchState<ForwardFlow> ForwardSearchState;
public:
    int step() const { return 1; }
    bool isIndexValid(int index, int size) { return (index < size); }
    void setParent(SearchState *current, SearchState *next)
        { next->addParent(current); }
    SearchState *makeSearchState(ControlFlowNode *node, Instruction *instruction)
        { return new ForwardSearchState(node, instruction); }
    SearchState *makeSearchState(const SearchState &other)
        { return new ForwardSearchState(other); }
};

class SlicingSearch {
private:
    ControlFlowGraph *cfg;
    std::vector<SearchState *> stateList;  // history of states
    std::vector<SearchState *> conditions;  // conditional jumps
    SlicingHalt *halt;

public:
    SlicingSearch(ControlFlowGraph *cfg, SlicingHalt *halt = nullptr)
        : cfg(cfg), halt(halt) {}
    virtual ~SlicingSearch();

    /** Run search beginning at this instruction. */
    void sliceAt(Instruction *instruction, int reg);

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

    bool shouldContinue(SearchState *currentState);

private:
    virtual int getStep() const = 0;
    virtual bool isIndexValid(ChunkList *list, int index) = 0;
    virtual bool isIndexValid(std::vector<SearchState *> &list, int index) = 0;
    virtual void setParent(SearchState *current, SearchState *next) = 0;
    virtual SearchState *makeSearchState(ControlFlowNode *node, Instruction *instruction) = 0;
    virtual SearchState *makeSearchState(const SearchState& other) = 0;
};

template <typename SlicingDirector>
class DirectedSlicingSearch : public SlicingSearch {
public:
    DirectedSlicingSearch(ControlFlowGraph *cfg, SlicingHalt *halt = nullptr)
        : SlicingSearch(cfg, halt) {}

private:
    virtual int getStep() const { return SlicingDirector().step(); }
    virtual void setParent(SearchState *current, SearchState *next)
        { SlicingDirector().setParent(current, next); }
    virtual bool isIndexValid(ChunkList *list, int index)
        { return SlicingDirector().isIndexValid(index,
               static_cast<int>(list->genericGetSize())); }
    virtual bool isIndexValid(std::vector<SearchState *> &list, int index)
        { return SlicingDirector().isIndexValid(index,
               static_cast<int>(list.size())); }
    virtual SearchState *makeSearchState(ControlFlowNode *node, Instruction *instruction)
        { return SlicingDirector().makeSearchState(node, instruction); }
    virtual SearchState *makeSearchState(const SearchState& other)
        { return SlicingDirector().makeSearchState(other); }
};

typedef DirectedSlicingSearch<BackwardSlicing> BackwardSlicingSearch;
typedef DirectedSlicingSearch<ForwardSlicing> ForwardSlicingSearch;

#endif
