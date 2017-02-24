#include <iomanip>
#include <sstream>
#include "slicing.h"
#include "slicingtree.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "log/log.h"

TreeNode *SearchState::getRegTree(int reg) {
    auto it = regTree.find(reg);
    return (it != regTree.end() ? (*it).second : nullptr);
}

void SearchState::setRegTree(int reg, TreeNode *tree) {
    regTree[reg] = tree;
}

const char *SlicingUtilities::printReg(int reg) {
    Disassemble::Handle handle(true);
    return cs_reg_name(handle.raw(), reg);
}

void SlicingUtilities::printRegs(SearchState *state, bool withNewline) {
    std::ostringstream output;
    output << "[";

    bool firstReg = true;
    const auto &regs = state->getRegs();
    for(size_t r = 0; r < regs.size(); r ++) {
        if(!regs[r]) continue;

        if(!firstReg) output << " ";
        firstReg = false;
        output << printReg(r);
    }
    output << "]";

    LOG0(1, "    regs " << std::left << std::setw(30)
        << output.str());

    if(withNewline) LOG(1, "");
}

void SlicingUtilities::printRegTrees(SearchState *state) {
    const auto &regs = state->getRegs();
    for(size_t r = 0; r < regs.size(); r ++) {
        auto tree = state->getRegTree(r);
        if(!tree) continue;

        LOG0(2, "        REG " << printReg(r) << ": ");
        IF_LOG(2) tree->print(TreePrinter(3, 1));
        LOG(2, "");
    }
}

void SlicingUtilities::copyParentRegTrees(SearchState *state) {
    const auto &regs = state->getRegs();
    for(size_t r = 0; r < regs.size(); r ++) {
        if(regs[r] && !state->getRegTree(r)) {
            // didn't compute this register yet, copy from parent(s)
            state->setRegTree(r, getParentRegTree(state, r));
        }
    }
}

TreeNode *SlicingUtilities::makeMemTree(SearchState *state, x86_op_mem *mem) {
    TreeNode *tree = nullptr;
    if(mem->index != X86_REG_INVALID) {
        tree = getParentRegTree(state, mem->index);
        if(mem->scale != 1) {
            tree = new TreeNodeMultiplication(
                tree,
                new TreeNodeConstant(mem->scale));
        }
    }

    TreeNode *baseTree = getParentRegTree(state, mem->base);
    if(mem->base != X86_REG_INVALID) {
        if(tree) {
            tree = new TreeNodeAddition(baseTree, tree);
        }
        else {
            tree = baseTree;
        }
    }

    if(mem->disp) {
        if(tree) {
            tree = new TreeNodeAddition(
                new TreeNodeAddress(mem->disp), tree);
        }
        else {
            tree = new TreeNodeAddress(mem->disp);
        }
    }

    return tree;
}

TreeNode *SlicingUtilities::getParentRegTree(SearchState *state, int reg) {
    if(reg == X86_REG_RIP) {
        // evaluate the instruction pointer in-place
        auto i = state->getInstruction();
        return new TreeNodeRegisterRIP(i->getAddress() + i->getSize());
    }

    const auto &parents = state->getParents();
    if(parents.size() == 0) {
        // no parents, the register value must have originated here
        return new TreeNodeRegister(reg);
    }
    else if(parents.size() == 1) {
        // common case: exactly one parent, use its register tree
        auto tree = parents.front()->getRegTree(reg);
        if(!tree) {
            // This should only happen the first time a reg is used.
            tree = new TreeNodeRegister(reg);  // parent doesn't have this
        }
        return tree;
    }
    else {
        // unusual case: multiple parents, combine with branching node
        auto tree = new TreeNodeMultipleParents();
        for(auto p : parents) {
            auto t = p->getRegTree(reg);
            if(!t) t = new TreeNodeRegister(reg);
            tree->addParent(t);
        }
        return tree;
    }
}

void SlicingSearch::sliceAt(Instruction *i) {
    auto block = dynamic_cast<Block *>(i->getParent());
    auto node = cfg->get(block);
    LOG(1, "begin slicing at " << i->getName());

    SearchState *startState = new SearchState(node, i);
    auto j = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic());
    startState->addReg(j->getRegister());

    buildStatePass(startState);
    buildRegTreePass();
}

void SlicingSearch::buildStatePass(SearchState *startState) {
    // We perform a breadth-first search through parent CFG nodes
    // and generate this->stateList.
    std::vector<bool> visited(cfg->getCount());  // indexed by node ID
    // This stores transitions to new states (basic blocks):
    std::vector<SearchState *> transitionList;

    transitionList.push_back(startState);

    // NOTE: we only visit each parent CFG node once, even though there
    // may be multiple paths to it, e.g. by taking a jump or not. This means
    // detecting certain cases like conditional-jumping into the next block
    // may result in invalid bounds calculations.
    while(transitionList.size() > 0) {
        SearchState *currentState = transitionList.front();
        transitionList.erase(transitionList.begin());  // inefficient
        auto node = currentState->getNode();
        Instruction *instruction = currentState->getInstruction();

        if(visited[node->getID()]) continue;
        visited[node->getID()] = true;

        LOG(1, "visit " << node->getDescription());

        // visit all prior instructions in this node in backwards order
        auto insList = node->getBlock()->getChildren()->getIterable();
        for(int index = insList->indexOf(instruction); index >= 0; index --) {
            Instruction *i = insList->get(index);
            ChunkDumper dumper;
            dumper.visit(i);

            currentState->setInstruction(i);

            bool stillSearching = false;
            for(auto r : currentState->getRegs()) {
                if(r) {
                    stillSearching = true;
                    break;
                }
            }
            if(!stillSearching) continue;

            buildStateFor(currentState);
            stateList.push_back(currentState);

            if(index > 0) {
                auto newState = new SearchState(*currentState);
                currentState->addParent(newState);
                currentState = newState;
            }
        }

        // find all nodes that link to this one, keep searching there
        for(auto link : node->backwardLinks()) {
            auto newNode = cfg->get(link.getID());
            if(!visited[newNode->getID()]) {
                auto offset = link.getOffset();
                Instruction *newStart
                    = newNode->getBlock()->getChildren()->getSpatial()->find(
                        newNode->getBlock()->getAddress() + offset);
                LOG(1, "    start at offset " << offset << " -> " << newStart);
                SearchState *newState = new SearchState(*currentState);
                newState->setNode(newNode);
                newState->setInstruction(newStart);
                newState->setJumpTaken(link.getFollowJump());
                transitionList.push_back(newState);
                currentState->addParent(newState);
            }
        }
    }
}

void SlicingSearch::buildRegTreePass() {
    LOG(1, "second pass iteration");
    for(auto it = stateList.rbegin(); it != stateList.rend(); ++it) {
        auto state = (*it);
        auto instruction = state->getInstruction();

        SlicingUtilities u;
        u.printRegs(state, false);
        ChunkDumper dumper;
        dumper.visit(instruction);

        buildRegTreesFor(state);
        u.copyParentRegTrees(state);  // inherit interesting regs from parent
        u.printRegTrees(state);
    }
}

void SlicingSearch::debugPrintRegAccesses(Instruction *i) {
    auto capstone = i->getSemantic()->getCapstone();
    if(!capstone || !capstone->detail) return;
    auto detail = capstone->detail;

    SlicingUtilities u;

    for(size_t r = 0; r < detail->regs_read_count; r ++) {
        LOG(1, "        implicit reg read "
            << u.printReg(detail->regs_read[r]));
    }
    for(size_t r = 0; r < detail->regs_write_count; r ++) {
        LOG(1, "        implicit reg write "
            << u.printReg(detail->regs_write[r]));
    }

#ifdef ARCH_X86_64
    cs_x86 *x = &detail->x86;
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &detail->arm64;
#endif
    for(size_t p = 0; p < x->op_count; p ++) {
        auto op = &x->operands[p];  // cs_x86_op*, cs_arm64_op*
        if(static_cast<cs_op_type>(op->type) == CS_OP_REG) {
            LOG(1, "        explicit reg ref "
                << u.printReg(op->reg));
        }
    }
}

class SlicingInstructionState {
public:
    enum Mode {
        MODE_UNKNOWN,
        MODE_REG_REG,
        MODE_MEM_REG,
        MODE_IMM_REG,
    };
private:
    SearchState *state;
    Mode mode;
    union arg1_t {
        x86_reg reg;
        x86_op_mem *mem;
        unsigned long imm;
    } a1;
    union arg2_t {
        x86_reg reg;
    } a2;
public:
    SlicingInstructionState(SearchState *state, cs_insn *capstone)
        : state(state) { determineMode(capstone); }

    arg1_t *get1() { return &a1; }
    arg2_t *get2() { return &a2; }
    Mode getMode() const { return mode; }

    void defaultDetectRegReg(bool overwriteTarget);
    void defaultDetectMemReg(bool overwriteTarget);
    void defaultDetectImmReg(bool overwriteTarget);
private:
    void determineMode(cs_insn *capstone);
    bool convertRegisterSize(x86_reg &reg);
};

void SlicingInstructionState::determineMode(cs_insn *capstone) {
    mode = MODE_UNKNOWN;
#ifdef ARCH_X86_64
    cs_x86 *x = &capstone->detail->x86;
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &capstone->detail->arm64;
#endif
    if(x->op_count == 2
        && x->operands[0].type == X86_OP_REG
        && x->operands[1].type == X86_OP_REG) {

        mode = MODE_REG_REG;
        a1.reg = x->operands[0].reg;
        a2.reg = x->operands[1].reg;
    }
    if(x->op_count == 2
        && x->operands[0].type == X86_OP_MEM
        && x->operands[1].type == X86_OP_REG) {

        mode = MODE_MEM_REG;
        a1.mem = &x->operands[0].mem;
        a2.reg = x->operands[1].reg;
    }
    if(x->op_count == 2
        && x->operands[0].type == X86_OP_IMM
        && x->operands[1].type == X86_OP_REG) {

        mode = MODE_IMM_REG;
        a1.imm = x->operands[0].imm;
        a2.reg = x->operands[1].reg;
    }
}

bool SlicingInstructionState::convertRegisterSize(x86_reg &reg) {
    if(state->getReg(reg)) {
        return false;  // We are already looking for this exact register
    }

    x86_reg promotion[][4] = {
        // ignoring AH etc for now
        {X86_REG_AL, X86_REG_AX, X86_REG_EAX, X86_REG_RAX},
        {X86_REG_BL, X86_REG_BX, X86_REG_EBX, X86_REG_RBX},
        {X86_REG_CL, X86_REG_CX, X86_REG_ECX, X86_REG_RCX},
        {X86_REG_DL, X86_REG_DX, X86_REG_EDX, X86_REG_RDX},
        {X86_REG_SI, X86_REG_ESI, X86_REG_RSI},  // 0 == X86_REG_INVALID
        {X86_REG_DI, X86_REG_EDI, X86_REG_RDI},
        {X86_REG_BP, X86_REG_EBP, X86_REG_RBP},
        {X86_REG_SP, X86_REG_EBP, X86_REG_RBP},
        {X86_REG_R8B, X86_REG_R8W, X86_REG_R8D, X86_REG_R8},
        {X86_REG_R9B, X86_REG_R9W, X86_REG_R9D, X86_REG_R9},
        {X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10},
        {X86_REG_R11B, X86_REG_R11W, X86_REG_R11D, X86_REG_R11},
        {X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12},
        {X86_REG_R13B, X86_REG_R13W, X86_REG_R13D, X86_REG_R13},
        {X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14},
        {X86_REG_R15B, X86_REG_R15W, X86_REG_R15D, X86_REG_R15}
    };

    for(size_t i = 0; i < sizeof(promotion)/sizeof(*promotion); i ++) {
        for(size_t j = 0; j < sizeof(*promotion)/sizeof(**promotion); j ++) {
            if(promotion[i][j] == reg) {
                for(j ++; j < sizeof(*promotion)/sizeof(**promotion); j ++) {
                    if(!promotion[i][j]) break;

                    if(state->getReg(promotion[i][j])) {
                        reg = promotion[i][j];
                        return true;
                    }
                }
                break;
            }
        }
    }

#if 0
    // try promoting registers rax, rbp, rbx, rcx, rdi, rdx
    if(r >= X86_REG_AX && r <= X86_REG_DX) {
        r += (X86_REG_EAX - X86_REG_AX);
        if(state->getReg(r)) {
            reg = x86_reg(r);
            return true;
        }
    }
#endif

    return false;
}

void SlicingInstructionState::defaultDetectRegReg(bool overwriteTarget) {
    convertRegisterSize(a2.reg);
    auto source = a1.reg;
    auto target = a2.reg;

    if(state->getReg(target)) {
        state->addReg(source);
        if(overwriteTarget) {
            state->removeReg(target);
        }
    }
}
void SlicingInstructionState::defaultDetectMemReg(bool overwriteTarget) {
    convertRegisterSize(a2.reg);
    auto mem = a1.mem;
    auto reg = a2.reg;

    if(state->getReg(reg)) {
        if(overwriteTarget) {
            state->removeReg(reg);
        }
        if(mem->base != X86_REG_INVALID) {
            state->addReg(mem->base);
        }
        if(mem->index != X86_REG_INVALID) {
            state->addReg(mem->index);
        }
    }
}
void SlicingInstructionState::defaultDetectImmReg(bool overwriteTarget) {
    convertRegisterSize(a2.reg);
    //auto imm = a1.imm;
    auto reg = a2.reg;

    if(state->getReg(reg)) {
        if(overwriteTarget) {
            state->removeReg(reg);
        }
    }
}

void SlicingSearch::buildStateFor(SearchState *state) {
    auto capstone = state->getInstruction()->getSemantic()->getCapstone();

    debugPrintRegAccesses(state->getInstruction());

    detectInstruction(state, true);

    if(capstone && capstone->detail) {
        // if any instruction overwrites EFLAGS, remove from reg set
        for(size_t r = 0; r < capstone->detail->regs_write_count; r ++) {
            if(capstone->detail->regs_write[r] == X86_REG_EFLAGS) {
                state->removeReg(X86_REG_EFLAGS);
            }
        }
    }

    state->removeReg(X86_REG_RIP);  // never care about this
}

void SlicingSearch::buildRegTreesFor(SearchState *state) {
    detectInstruction(state, false);
}

void SlicingSearch::detectInstruction(SearchState *state, bool firstPass) {
    auto capstone = state->getInstruction()->getSemantic()->getCapstone();
    if(!capstone || !capstone->detail) {
        detectJumpRegTrees(state, firstPass);
        return;
    }

    SlicingUtilities u;

    SlicingInstructionState *iState;
    if(firstPass) {
        iState = new SlicingInstructionState(state, capstone);
        state->setIState(iState);
    }
    else {
        iState = state->getIState();
    }
    auto mode = iState->getMode();

    switch(capstone->id) {
    case X86_INS_ADD:
        if(mode == SlicingInstructionState::MODE_REG_REG) {
            if(firstPass) {
                iState->defaultDetectRegReg(false);
            }
            else {
                auto source = iState->get1()->reg;
                auto target = iState->get2()->reg;

                state->setRegTree(target, new TreeNodeAddition(
                    u.getParentRegTree(state, source),
                    u.getParentRegTree(state, target)));
            }
        }
        LOG(1, "        add found");
        break;
    case X86_INS_LEA:
        if(mode == SlicingInstructionState::MODE_MEM_REG) {
            if(firstPass) {
                iState->defaultDetectMemReg(true);
            }
            else {
                auto mem = iState->get1()->mem;
                auto reg = iState->get2()->reg;

                auto tree = u.makeMemTree(state, mem);
                state->setRegTree(reg, tree);
            }
        }
        LOG(1, "        lea found");
        break;
    case X86_INS_MOV:
        if(mode == SlicingInstructionState::MODE_REG_REG) {
            if(firstPass) {
                iState->defaultDetectRegReg(true);
            }
            else {
                auto source = iState->get1()->reg;
                auto target = iState->get2()->reg;

                state->setRegTree(target,
                    u.getParentRegTree(state, source));
            }
        }
        else if(mode == SlicingInstructionState::MODE_MEM_REG) {
            if(firstPass) {
                iState->defaultDetectMemReg(true);
            }
            else {
                auto mem = iState->get1()->mem;
                auto reg = iState->get2()->reg;

                auto tree = u.makeMemTree(state, mem);
                state->setRegTree(reg, tree);
            }
        }
        LOG(1, "        mov found");
        break;
    case X86_INS_MOVSXD:
        if(mode == SlicingInstructionState::MODE_MEM_REG) {
            if(firstPass) {
                iState->defaultDetectMemReg(true);
            }
            else {
                auto mem = iState->get1()->mem;
                auto reg = iState->get2()->reg;

                auto tree = u.makeMemTree(state, mem);
                state->setRegTree(reg, tree);
            }
        }

        LOG(1, "        movslq found");
        break;
    case X86_INS_MOVZX:
        if(mode == SlicingInstructionState::MODE_REG_REG) {
            if(firstPass) {
                iState->defaultDetectRegReg(true);
            }
            else {
                auto source = iState->get1()->reg;
                auto target = iState->get2()->reg;

                state->setRegTree(target,
                    u.getParentRegTree(state, source));
            }
        }
        else if(mode == SlicingInstructionState::MODE_MEM_REG) {
            if(firstPass) {
                iState->defaultDetectMemReg(true);
            }
            else {
                auto mem = iState->get1()->mem;
                auto target = iState->get2()->reg;

                auto tree = u.makeMemTree(state, mem);
                state->setRegTree(target, tree);
            }
        }
        LOG(1, "        movzx found");
        break;
    case X86_INS_CMP:
        if(mode == SlicingInstructionState::MODE_IMM_REG) {
            auto imm = iState->get1()->imm;
            auto reg = iState->get2()->reg;

            if(firstPass) {
                iState->defaultDetectImmReg(false);
                state->addReg(reg);
            }
            else {
                state->setRegTree(X86_REG_EFLAGS,
                    new TreeNodeComparison(
                        new TreeNodeConstant(imm),
                        u.getParentRegTree(state, reg)));
            }
        }
        break;
    default:
        LOG(1, "        got instr id " << capstone->id);
        break;
    }
}

void SlicingSearch::detectJumpRegTrees(SearchState *state, bool firstPass) {
    SlicingUtilities u;
    auto semantic = state->getInstruction()->getSemantic();
    if(auto v = dynamic_cast<ControlFlowInstruction *>(semantic)) {
        if(v->getMnemonic() != "jmp" && v->getMnemonic() != "callq") {
            if(firstPass) {
                state->addReg(X86_REG_EFLAGS);
            }
            else {
                LOG0(1, "    found a conditional jump, eflags is ");
                //auto tree = state->getRegTree(X86_REG_EFLAGS);
                auto tree = u.getParentRegTree(state, X86_REG_EFLAGS);
                if(tree) {
                    IF_LOG(1) tree->print(TreePrinter(2, 0));
                }
                else LOG0(1, "NULL");
                LOG(1, "");

                state->setRegTree(X86_REG_EFLAGS, tree);

                conditions.push_back(state);
            }
        }
    }
}
