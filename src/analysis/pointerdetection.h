#ifndef EGALITO_ANALYSIS_POINTERDETECTION_H
#define EGALITO_ANALYSIS_POINTERDETECTION_H

#include <vector>
#include "types.h"
#include "analysis/walker.h"
#include "analysis/usedef.h"
#include "analysis/controlflow.h"
#include "analysis/slicingmatch.h"

class ControlFlowGraph;
class Function;
class Instruction;

class PointerDetection {
private:
    Function *function;
    ControlFlowGraph cfg;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodePhysicalRegister>>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > PointerForm;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternCapture<PointerForm>
    > PointerDerefForm;

    // just for comparing against slicing
    std::map<Instruction *, address_t> found;

public:
    PointerDetection(Function *function) : function(function), cfg(function) {}
    void detect();

private:
    void detectPointers(UDState *state, TreeNode *tree);
    void checkLink(Instruction *instruction, address_t target);
};

struct PointerPageNode {
    TreeNodeAddress *tree;
    UDState *owner;

    PointerPageNode(TreeNodeAddress *tree, UDState *owner)
        : tree(tree), owner(owner) {}
};

class PointerPageNodeDetection {
private:
    std::vector<PointerPageNode> list;
    std::map<UDState *, std::vector<int>> seen;

public:
    void detectFor(UDState *state, int reg);
    void detectHelper(UDState *state, int reg);
    const std::vector<PointerPageNode>& getList() const { return list; }
    size_t getCount() const { return list.size(); }
};

#endif
