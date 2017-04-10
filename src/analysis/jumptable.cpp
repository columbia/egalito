#include <capstone/capstone.h>
#include "jumptable.h"
#include "controlflow.h"
#include "instr/concrete.h"
#include "slicing.h"
#include "slicingtree.h"
#include "slicingmatch.h"

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
        if(dynamic_cast<IndirectJumpInstruction *>(i->getSemantic())) {
            SlicingSearch search(&cfg);
            search.sliceAt(i);

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

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternLEA,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternLEA>,
            TreePatternBinary<TreeNodeMultiplication,
                TreePatternCapture<TreePatternAny>,
                TreePatternConstantIs<4>>
        >
    > Form1;
#elif defined(ARCH_AARCH64)
    typedef TreePatternTerminal<TreeNodeAddress> TreePatternTargetBase;

    // base address could have been saved on stack
    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternAny>,
        TreePatternCapture<TreePatternAny>
    > TreePatternTableEntry;

    typedef TreePatternBinary<TreeNodeLogicalShiftLeft,
        TreePatternUnary<TreeNodeDereference, TreePatternTableEntry>,
        TreePatternConstantIs<2>
    > TreePatternTargetOffset;

    typedef TreePatternBinary<TreeNodeAddition,
            TreePatternTargetBase,
            TreePatternTargetOffset
    > Form1;
#endif

    TreeCapture capture;
    if(Form1::matches(tree, capture)) {
        LOG(1, "found jump table jump:");

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
        d->setScale(4);
        d->setIndexExpr(capture.get(1));
        // indexRegister is not known right now.
#elif defined(ARCH_AARCH64)
        TreeNode *tableAddress = capture.get(0);
        LOG0(1, "    address of jump table: ");
        IF_LOG(1) tableAddress->print(TreePrinter(1, 0));
        std::vector<address_t> baseAddresses = getTableAddresses(state,
                                                                 tableAddress);
        if(baseAddresses.size() == 0) {
            LOG(1, "couldn't parse the table address");
            return false;
        }
        else if(baseAddresses.size() > 1) {
            LOG(1, "-- considering only the first table");
        }
        LOG(1, "  => 0x" << std::hex << baseAddresses.front());

        TreeNode *indexExpr = capture.get(1);
        if (auto p = dynamic_cast<TreeNodeLogicalShiftLeft *>(indexExpr)) {
            indexExpr = p->getLeft();
        }
        LOG0(1, "    indexing expression:   ");
        IF_LOG(1) indexExpr->print(TreePrinter(1, 0));
        LOG(1, "");


        d->setAddress(baseAddresses.front());
        d->setScale(4);
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
#elif defined(ARCH_AARCH64)
        auto tree = state->getRegTree(ARM64_REG_NZCV);
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
#elif defined(ARCH_AARCH64)
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
        else {
            // this single level intepretation seems to be enought for AARCH64
            if(auto mult = dynamic_cast<TreeNodeMultipleParents *>(indexExpr)) {
                for(auto sub : mult->getParents()) {
                    if(leftGeneric == sub
                       && (op == OP_LE || op == OP_LT)) {
                        LOG0(5, "BOUNDS CHECK (MIGHT BE) FOUND! ");

                        if(op == OP_LT) bound --;  // convert "<" to "<="
                        d->setBound(bound);

                        return true;
                    }
                }
            }
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

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>,
            TreePatternCapture<TreePatternAny>
        >
    > TreePatternTableBase;

    typedef TreePatternUnary<TreeNodeDereference,
        TreePatternBinary<TreeNodeAddition,
            TreePatternCapture<TreePatternAny>,
            TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
        >
    > TreePatternTableBase2;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>,
        TreePatternCapture<TreePatternAny>
    > TreePatternTableBaseAddress;

    typedef TreePatternBinary<TreeNodeAddition,
        TreePatternCapture<TreePatternAny>,
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>
    > TreePatternTableBaseAddress2;

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

    TreeCapture *cap1, cap11, cap12;
    int constant_idx1;
    int any_idx1;
    if(TreePatternTableBase::matches(tree, cap11)) {
        constant_idx1 = 0;
        any_idx1 = 1;
        cap1 = &cap11;
    }
    else if(TreePatternTableBase2::matches(tree, cap12)) {
        any_idx1 = 0;
        constant_idx1 = 1;
        cap1 = &cap12;
    }
    else {
        LOG(1, "this doesn't match the table base pattern");
        IF_LOG(1) tree->print(TreePrinter(2, 0));
        LOG(1, "");
        return baseAddresses;
    }

    for(auto const &m : state->getMemTree()) {
        TreeCapture *cap2, cap21, cap22;
        int constant_idx2;
        int any_idx2;
        if(TreePatternTableBase::matches(m.first, cap21)) {
            constant_idx2 = 0;
            any_idx2 = 1;
            cap2 = &cap21;
        }
        else if(TreePatternTableBase2::matches(m.first, cap22)) {
            any_idx2 = 0;
            constant_idx2 = 1;
            cap2 = &cap22;
        }
        else {
            continue;
        }
        auto c1 = dynamic_cast<TreeNodeConstant *>(cap1->get(constant_idx1));
        auto c2 = dynamic_cast<TreeNodeConstant *>(cap2->get(constant_idx2));
        if(c1->getValue() == c2->getValue()) {
            if(auto base = dynamic_cast<TreeNodeAddress *>(m.second)) {
                address_t ba = c1->getValue() + base->getValue();
                baseAddresses.push_back(ba);
            }
            else {
                auto mult = dynamic_cast<TreeNodeMultipleParents *>(
                    cap2->get(any_idx2));

                if(mult && mult->canbe(cap1->get(any_idx1))) {

                    TreeCapture *cap3, cap31, cap32;
                    int constant_idx3;
                    int any_idx3;

                    if(TreePatternTableBaseAddress::matches(m.second, cap31)) {
                        constant_idx3 = 0;
                        any_idx3 = 1;
                        cap3 = &cap31;
                    }
                    else if(TreePatternTableBaseAddress2::matches(
                        m.second, cap32)) {

                        any_idx3 = 0;
                        constant_idx3 = 1;
                        cap3 = &cap32;
                    }
                    else {
                        continue;
                    }

                    if(auto base = findAddressInParents(state,
                        cap3->get(any_idx3))) {

                        if(auto off = findConstantInParents(state,
                            cap3->get(constant_idx3))) {

                            address_t addr = base->getValue() + off->getValue();
                            baseAddresses.push_back(addr);
                        }
                    }
                }
            }
        }
    }

    return baseAddresses;
}
