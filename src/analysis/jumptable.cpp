#include <capstone/capstone.h>
#include "jumptable.h"
#include "controlflow.h"
#include "chunk/instruction.h"
#include "slicing.h"
#include "slicingtree.h"
#include "slicingmatch.h"

#include "types.h"
#include "log/log.h"

void JumpTableSearch::search(Module *module) {
    for(auto f : module->getChildren()->getIterable()->iterable()) {
        search(f);
    }
}

void JumpTableSearch::search(Function *function) {
    ControlFlowGraph cfg(function);

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        auto i = b->getChildren()->getIterable()->getLast();
        if(dynamic_cast<IndirectJumpInstruction *>(i->getSemantic())) {
            SlicingSearch search(&cfg);
            search.sliceAt(i);

            matchJumpTable(search.getInitialState());
        }
    }
}

void JumpTableSearch::matchJumpTable(SearchState *state) {
    auto i = state->getInstruction();
    auto v = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic());
    if(!v) return;

    // get final tree for pattern matching
    auto tree = state->getRegTree(v->getRegister());

    typedef TreePatternRegisterIs<X86_REG_RIP> TreePatternRIP;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternTerminal<TreeNodeAddress>,
        TreePatternRIP
    > TreePatternLEA;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternLEA,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternLEA>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<TreePatternAny>,
                TreePatternConstantIs<4>>
        >
    > Form1;

    TreeCapture capture;
    if(Form1::matches(tree, capture)) {
        LOG(1, "FOUND JUMP TABLE BY PATTERN MATCHING!!!");

        LOG0(1, "address of jump table: ");
        auto node = dynamic_cast<TreeNodeAddition *>(capture.get(0));
        auto left = dynamic_cast<TreeNodeAddress *>(node->getLeft());
        auto right = dynamic_cast<TreeNodeRegisterRIP *>(node->getRight());
        capture.get(0)->print(TreePrinter(1, 0));
        LOG(1, "  => 0x" << std::hex << left->getValue() + right->getValue());

        LOG0(1, "indexing expression:   ");
        capture.get(1)->print(TreePrinter(1, 0));
        LOG(1, "");
    }
}
