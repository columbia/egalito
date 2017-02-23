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

            if(matchJumpTable(search.getInitialState())
                && matchJumpTableBounds(&search)) {

                LOG(1, "FOUND JUMP TABLE BY PATTERN MATCHING!!!");
            }
        }
    }
}

bool JumpTableSearch::matchJumpTable(SearchState *state) {
    auto i = state->getInstruction();
    auto v = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic());
    if(!v) return false;

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
        LOG(1, "found jump table jump:");

        LOG0(1, "    address of jump table: ");
        auto node = dynamic_cast<TreeNodeAddition *>(capture.get(0));
        auto left = dynamic_cast<TreeNodeAddress *>(node->getLeft());
        auto right = dynamic_cast<TreeNodeRegisterRIP *>(node->getRight());
        capture.get(0)->print(TreePrinter(1, 0));
        LOG(1, "  => 0x" << std::hex << left->getValue() + right->getValue());

        LOG0(1, "    indexing expression:   ");
        capture.get(1)->print(TreePrinter(1, 0));
        LOG(1, "");

        this->indexExpr = capture.get(1);

        return true;
    }

    return false;
}

bool JumpTableSearch::matchJumpTableBounds(SlicingSearch *search) {
    for(auto state : search->getConditionList()) {
        auto tree = state->getRegTree(X86_REG_EFLAGS);
        auto condition = dynamic_cast<TreeNodeComparison *>(tree);
        if(!condition) continue;

        auto leftGeneric = condition->getLeft();
        auto rightGeneric = condition->getRight();
        auto left = dynamic_cast<TreeNodeConstant *>(condition->getLeft());
        auto right = dynamic_cast<TreeNodeConstant *>(condition->getRight());
        if(!left && !right) continue;

        enum Operator {
            OP_LT = 1,
            OP_LE = 2,
            OP_NE = 4,
            OP_EQ = 10-OP_NE,
            OP_GE = 10-OP_LT,
            OP_GT = 10-OP_LE
        } op;
        const char *opString[] = {0, "<", "<=", 0, "!=", 0, "==", 0, ">=", ">"};

        auto semantic = state->getInstruction()->getSemantic();
        auto v = dynamic_cast<ControlFlowInstruction *>(semantic);
        if(!v) continue;
        std::string mnemonic = v->getMnemonic();
        if(mnemonic == "ja") op = OP_GT;
        else if(mnemonic == "jb") op = OP_LT;
        else if(mnemonic == "jne") op = OP_NE;
        else if(mnemonic == "je") op = OP_EQ;
        else {
            LOG(1, "what is " << mnemonic << "?");
            throw "unimplemented mnemonic in jump table slicing";
        }

        if(!state->getJumpTaken()) {
            op = Operator(10-int(op));
        }

        // we want the bounded value
        op = Operator(10-int(op));

        if(left && !right) {
            auto t = left;
            left = right;
            right = t;
            auto tt = leftGeneric;
            leftGeneric = rightGeneric;
            rightGeneric = tt;

            op = Operator(10-int(op));
        }

        unsigned long bound = right->getValue();
        LOG0(1, "comparison of ");
        leftGeneric->print(TreePrinter(2, 0));
        LOG(1, " is " << opString[op] << " " << std::dec << bound);

        if(leftGeneric == indexExpr && (op == OP_LE || op == OP_LT)) {
            LOG0(1, "BOUNDS CHECK FOUND! ");
            indexExpr->print(TreePrinter(2, 0));
            LOG(1, " is " << opString[op] << " " << std::dec << bound);
        }
    }

    return false;
}
