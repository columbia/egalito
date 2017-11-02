#include <capstone/capstone.h>
#include "jumptable.h"
#include "controlflow.h"
#include "instr/concrete.h"
#include "slicing.h"
#include "slicingtree.h"
#include "slicingmatch.h"
#include "util/timing.h"

#include "types.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP djumptable
#include "log/log.h"

long JumpTableDescriptor::getEntries() const {
    if(!isBoundKnown()) return -1;
    return bound + 1;
}

void JumpTableSearch::search(Module *module) {
    for(auto f : CIter::functions(module)) {
        search(f);
    }
}

void JumpTableSearch::search(Function *function) {
    ControlFlowGraph cfg(function);

    for(auto b : CIter::children(function)) {
        auto i = b->getChildren()->getIterable()->getLast();
        if(auto j = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic())) {
            BackwardSlicingSearch search(&cfg);
            search.sliceAt(i, j->getRegister());
            LOG(1, "slicing at " << i->getName() << " in " << function->getName());

            //EgalitoTiming ttt("JumpTableSearch matching etc");
            JumpTableDescriptor descriptor(function, i);

            if(matchJumpTable(search.getInitialState(), &descriptor)
                && (matchJumpTableBounds(&search, &descriptor)
                    || savePartialInfoTables)) {

                LOG(1, "FOUND JUMP TABLE BY PATTERN MATCHING!!!");
                tableList.push_back(new JumpTableDescriptor(descriptor));
            }
        }
    }
}

bool JumpTableSearch::matchJumpTable(SearchState *state,
    JumpTableDescriptor *d) {

    auto i = state->getInstruction();
    auto v = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic());
    if(!v) return false;

    // get final tree for pattern matching
    auto tree = state->getRegTree(v->getRegister());

#ifdef ARCH_X86_64
    typedef TreePatternRegisterIs<X86_REG_RIP> TreePatternRIP;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternTerminal<TreeNodeAddress>,
        TreePatternRIP
    > TreePatternLEA;

    typedef TreePatternBinaryAnyOrder<TreeNodeAddition,
        TreePatternLEA,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternLEA>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<TreePatternAny>,
                TreePatternConstantIs<4>>
        >
    > Form1;

    typedef TreePatternBinaryAnyOrder<TreeNodeAddition,
        TreePatternAtLeastOneParent<TreePatternLEA>,
        TreePatternBinary<TreeNodeAddition,
            TreePatternAtLeastOneParent<TreePatternCapture<TreePatternLEA>>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<TreePatternAny>,
                TreePatternConstantIs<4>>
        >
    > Form1_MultipleParents;
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    typedef TreePatternTerminal<TreeNodeAddress> TreePatternTargetBase;

    // base address could have been saved on stack
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternAny>,                     // 2
            TreePatternCapture<TreePatternAny>>,                    // 3
        TreePatternConstantIs<0>
    > TreePatternTableEntry;

    typedef TreePatternBinary<TreeNodeLogicalShiftLeft,
        TreePatternCapture<                                         // 1
            TreePatternUnary<TreeNodeDereference, TreePatternTableEntry>>,
        TreePatternConstantIs<2>
    > TreePatternTargetOffset;

    typedef TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTargetBase>,              // 0
            TreePatternTargetOffset
    > Form1;
#endif

    TreeCapture capture;
    bool matched = false;
    if(Form1::matches(tree, capture)) {
        matched = true;
    }
#ifdef ARCH_X86_64
    else if(capture.clear() && Form1_MultipleParents::matches(tree, capture)) {
        matched = true;
    }
#endif

    if(matched) {
        LOG(1, "found jump table jump:");
        IF_LOG(1) tree->print(TreePrinter(1, 0));
        LOG(1, "");

#ifdef ARCH_X86_64
        LOG0(1, "    address of jump table: ");
        auto node = dynamic_cast<TreeNodeAddition *>(capture.get(0));
        auto left = dynamic_cast<TreeNodeAddress *>(node->getLeft());
        auto right = dynamic_cast<TreeNodeRegisterRIP *>(node->getRight());
        IF_LOG(1) capture.get(0)->print(TreePrinter(1, 0));
        LOG(1, "  => 0x" << std::hex << (left->getValue() + right->getValue()));

        LOG0(1, "    indexing expression:   ");
        IF_LOG(1) capture.get(1)->print(TreePrinter(1, 0));
        LOG(1, "");

        d->setAddress(left->getValue() + right->getValue());
        // assume relative jump tables
        d->setTargetBaseAddress(left->getValue() + right->getValue());
        d->setScale(4);
        d->setIndexExpr(capture.get(1));
        // indexRegister is not known right now.
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        auto targetBase = dynamic_cast<TreeNodeAddress *>(capture.get(0));

        auto scale = dynamic_cast<TreeNodeDereference *>(capture.get(1))
            ->getWidth();

        TreeNode *tableAddress = capture.get(2);
        LOG0(1, "    address of jump table: ");
        IF_LOG(1) tableAddress->print(TreePrinter(1, 0));
        LOG(1, "");
        std::vector<address_t> baseAddresses = getTableAddresses(state,
                                                                 tableAddress);
        if(baseAddresses.size() == 0) {
            LOG(1, "couldn't parse the table address");
            possibleMissList.push_back(i);
            return false;
        }
        else if(baseAddresses.size() > 1) {
            LOG(1, "-- considering only the first table");
        }
        LOG(1, "  => 0x" << std::hex << baseAddresses.front());

        TreeNode *indexExpr = capture.get(3);
        if (auto p = dynamic_cast<TreeNodeLogicalShiftLeft *>(indexExpr)) {
            indexExpr = p->getLeft();
        }
        LOG0(1, "    indexing expression:   ");
        IF_LOG(1) indexExpr->print(TreePrinter(1, 0));
        LOG(1, "");

        d->setAddress(baseAddresses.front());
        d->setTargetBaseAddress(targetBase->getValue());
        d->setScale(scale);
        d->setIndexExpr(indexExpr);
#endif
        return true;
    }

    return false;
}

bool JumpTableSearch::matchJumpTableBounds(SlicingSearch *search,
    JumpTableDescriptor *d) {

    for(auto state : search->getConditionList()) {
#ifdef ARCH_X86_64
        auto tree = state->getRegTree(X86_REG_EFLAGS);
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        auto tree = state->getRegTree(ARM64_REG_NZCV);
        LOG(11, "condition flag:");
        IF_LOG(11) tree->print(TreePrinter(2, 0));
        LOG(11, "");
#endif
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
#ifdef ARCH_X86_64
        if(mnemonic == "ja") op = OP_GT;
        else if(mnemonic == "jae") op = OP_GE;
        else if(mnemonic == "jb") op = OP_LT;
        else if(mnemonic == "jbe") op = OP_LE;
        else if(mnemonic == "jne") op = OP_NE;
        else if(mnemonic == "je") op = OP_EQ;
        else if(mnemonic == "jg") op = OP_GT;
        else if(mnemonic == "jge") op = OP_GE;
        else if(mnemonic == "jl") op = OP_LT;
        else if(mnemonic == "jle") op = OP_LE;
        else if(mnemonic == "js") {
            continue;   // this doesn't seem useful...
        }
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(mnemonic == "b.ls") op = OP_LT;
        else if(mnemonic == "b.eq") op = OP_EQ;
        else if(mnemonic == "b.le") op = OP_LE;
        else if(mnemonic == "b.lt") op = OP_LT;
        else if(mnemonic == "b.ne") op = OP_NE;
        else if(mnemonic == "b.hi") op = OP_GE;
        else if(mnemonic == "b.gt") op = OP_GT;
        else if(mnemonic == "cbz") op = OP_EQ;
        else if(mnemonic == "cbnz") op = OP_NE;
        else if(mnemonic == "tbz" || mnemonic == "tbnz") {
            continue;   // needs more complicated analysis
        }
#endif
        else {
            LOG(1, "what is " << mnemonic << "?");
            std::cerr << "what is " << mnemonic << "?\n";
            throw "unimplemented mnemonic in jump table slicing";
        }

        auto taken = state->getJumpTaken();
        if(left && !right) {
            auto t = left;
            left = right;
            right = t;
            auto tt = leftGeneric;
            leftGeneric = rightGeneric;
            rightGeneric = tt;

            op = Operator(10-int(op));
            taken = !taken;
        }

        if(!taken) {
            op = Operator(10-int(op));
        }

        unsigned long bound = right->getValue();
        LOG0(11, "comparison of ");
        IF_LOG(11) leftGeneric->print(TreePrinter(2, 0));
        LOG(11, " is " << opString[op] << " " << std::dec << bound);

        auto indexExpr = d->getIndexExpr();
        if(leftGeneric == indexExpr
            && (op == OP_LE || op == OP_LT)) {

            LOG0(5, "BOUNDS CHECK FOUND! ");
            IF_LOG(5) d->getIndexExpr()->print(TreePrinter(2, 0));
            LOG(5, " is " << opString[op] << " " << std::dec << bound);

            if(op == OP_LT) bound --;  // convert "<" to "<="
            d->setBound(bound);

            return true;
        }
    }

    return false;
}

static TreeNodeAddress *findAddressInParents(SearchState *state, TreeNode *tree) {
    if(auto addr = dynamic_cast<TreeNodeAddress *>(tree)) {
        return addr;
    }
    else if(auto mult = dynamic_cast<TreeNodeMultipleParents *>(tree)) {
        for(auto p : mult->getParents()) {
            if(auto addr = findAddressInParents(state, p)) {
                return addr;
            }
        }
    }
    return nullptr;
}

static TreeNodeConstant *findConstantInParents(SearchState *state, TreeNode *tree) {
    if(auto addr = dynamic_cast<TreeNodeConstant *>(tree)) {
        return addr;
    }
    else if(auto mult = dynamic_cast<TreeNodeMultipleParents *>(tree)) {
        for(auto p : mult->getParents()) {
            if(auto addr = findConstantInParents(state, p)) {
                return addr;
            }
        }
    }
    return nullptr;
}

std::vector<address_t> JumpTableSearch::getTableAddresses(SearchState *state,
    TreeNode *tree) {

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternAny>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > TreePatternTableBase;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternTableBase
    > TreePatternTableBaseLoad;

    std::vector<address_t> baseAddresses;

    if(auto a = dynamic_cast<TreeNodeAddress *>(tree)) {
        baseAddresses.push_back(a->getValue());
        return baseAddresses;
    }

    if(auto mult = dynamic_cast<TreeNodeMultipleParents *>(tree)) {
        for(auto p : mult->getParents()) {
            auto res = getTableAddresses(state, p);
            baseAddresses.insert(baseAddresses.end(), res.begin(), res.end());
        }
        return baseAddresses;
    }


    TreeCapture cap1;
    if(TreePatternTableBase::matches(tree, cap1)) {
        auto a = dynamic_cast<TreeNodeAddress *>(cap1.get(0));
        auto c = dynamic_cast<TreeNodeConstant *>(cap1.get(1));
        if(a && c) {
            baseAddresses.push_back(a->getValue() + c->getValue());
        }
        return baseAddresses;
    }

    cap1.clear();
    if(TreePatternTableBaseLoad::matches(tree, cap1)) {
        for(auto const &m : state->getMemTrees()) {
            TreeCapture cap2;
            if(!TreePatternTableBaseLoad::matches(m.first, cap2)) {
                continue;
            }

            auto c1 = dynamic_cast<TreeNodeConstant *>(cap1.get(1));
            auto c2 = dynamic_cast<TreeNodeConstant *>(cap2.get(1));
            if(c1->getValue() == c2->getValue()) {
                if(auto base = dynamic_cast<TreeNodeAddress *>(m.second)) {
                    address_t ba = base->getValue() + c1->getValue();
                    baseAddresses.push_back(ba);
                    break;
                }

                TreeCapture cap3;
                if(!TreePatternTableBase::matches(m.second, cap3)) {
                    continue;
                }
                if(auto base = findAddressInParents(state, cap3.get(0))) {
                    if(auto off = findConstantInParents(state,
                                                        cap3.get(1))) {
                        address_t ba = base->getValue() + off->getValue();
                        baseAddresses.push_back(ba);
                    }
                }
            }
        }
    }

    return baseAddresses;
}
