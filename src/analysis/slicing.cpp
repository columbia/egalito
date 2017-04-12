#include <iomanip>
#include <sstream>
#include "slicing.h"
#include "slicingtree.h"
#include "chunk/dump.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "log/log.h"

TreeNode *SearchState::getRegTree(int reg) {
    auto it = regTree.find(reg);
    return (it != regTree.end() ? (*it).second : nullptr);
}

void SearchState::setRegTree(int reg, TreeNode *tree) {
    regTree[reg] = tree;
}

void SearchState::addMemTree(TreeNode *memTree, TreeNode *regTree) {
    this->memTree.push_back(memTreeType(memTree, regTree));
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

    LOG0(11, "    regs " << std::left << std::setw(30)
        << output.str());

    if(withNewline) LOG(11, "");
}

void SlicingUtilities::printRegTrees(SearchState *state) {
    const auto &regs = state->getRegs();
    for(size_t r = 0; r < regs.size(); r ++) {
        auto tree = state->getRegTree(r);
        if(!tree) continue;

        if(r == X86_REG_INVALID) continue;

        LOG0(12, "        REG " << printReg(r) << ": ");
        IF_LOG(12) tree->print(TreePrinter(3, 1));
        LOG(12, "");
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

void SlicingUtilities::printMemTrees(SearchState *state) {
    for(auto const &tree : state->getMemTree()) {
        LOG0(12, "        MEM ");
        IF_LOG(12) tree.first->print(TreePrinter(3,1));
        LOG0(12, ": ");
        IF_LOG(12) tree.second->print(TreePrinter(3, 1));
        LOG(12, "");
    }
}


TreeNode *SlicingUtilities::makeMemTree(SearchState *state,
    const x86_op_mem *mem) {

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

TreeNode *SlicingUtilities::makeMemTree(SearchState *state,
                                        const arm64_op_mem *mem,
                                        arm64_extender ext,
                                        arm64_shifter sft_type,
                                        unsigned int sft_value) {
#if 0
    LOG(11, "makeMemTree: ext = " << ext
        << " shift type = " << sft_type
        << " shift value = " << sft_value);
#endif
    TreeNode *tree = nullptr;
    if(mem->index != ARM64_REG_INVALID) {
        tree = getParentRegTree(state, mem->index);
#if 0
        if(ext != ARM64_EXT_INVALID) {
            if(ext == ARM64_EXT_UXTW) {
                tree = new TreeNodeUnsignedExtendWord(tree);
            }
            else {
                LOG(11, "unknown extender");
            }
        }
#endif
        if(sft_type != ARM64_SFT_INVALID) {
            if(sft_type  == ARM64_SFT_LSL) {
                tree = new TreeNodeLogicalShiftLeft(tree,
                    new TreeNodeConstant(sft_value));
            }
        }
    }

    TreeNode *baseTree = getParentRegTree(state, mem->base);
    if(mem->base != ARM64_REG_INVALID) {    // should be there always
        if(tree) {
            tree = new TreeNodeAddition(baseTree, tree);
        }
        else {
            tree = baseTree;
        }
    }
    if(mem->disp) {
        if(tree) {
            tree = new TreeNodeAddition(tree,
                new TreeNodeConstant(mem->disp));
        }
        else {
            tree = new TreeNodeConstant(mem->disp);
        }
    }

    return new TreeNodeDereference(tree);
}

TreeNode *SlicingUtilities::getParentRegTree(SearchState *state, int reg) {
#ifdef ARCH_X86_64
    if(reg == X86_REG_RIP) {
        // evaluate the instruction pointer in-place
        auto i = state->getInstruction();
        return new TreeNodeRegisterRIP(i->getAddress() + i->getSize());
    }
#endif

    const auto &parents = state->getParents();
    if(parents.size() == 0) {
        // no parents, the register value must have originated here
        auto tree = new TreeNodeRegister(reg);
        state->setRegTree(reg, tree);
        return tree;
    }
    else if(parents.size() == 1) {
        // common case: exactly one parent, use its register tree
        auto tree = parents.front()->getRegTree(reg);
        if(!tree) {
            // This should only happen the first time a reg is used.
            tree = new TreeNodeRegister(reg);   // parent doesn't have this
            state->setRegTree(reg, tree);
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
        state->setRegTree(reg, tree);
        return tree;
    }
}

void SlicingUtilities::copyParentMemTrees(SearchState *state) {
    const auto &parents = state->getParents();
    if(parents.size() == 0) {
    }
    else if(parents.size() == 1) {
        state->setMemTree(parents.front()->getMemTree());
    }
    else {
        auto memTree = state->getMemTree();
        size_t size = 0;
        for(auto p : parents) {
            size += p->getMemTree().size();
        }
        memTree.reserve(size);
        for(auto p : parents) {
            auto mt = p->getMemTree();
            if(mt.size() > 0) {
                memTree.insert(memTree.end(), mt.begin(), mt.end());
            }
        }
        state->setMemTree(memTree);
    }
}

void SlicingSearch::sliceAt(Instruction *instruction, int reg) {
    auto block = dynamic_cast<Block *>(instruction->getParent());
    auto node = cfg->get(block);
    LOG(11, "begin slicing at " << instruction->getName());

    SearchState *startState = new SearchState(node, instruction);
    startState->addReg(reg);

    buildStatePass(startState);
    buildRegTreePass();
}

bool SlicingSearch::isIndexValid(ChunkList *list, int index) {
    return (direction < 0 ? index >= 0
            : index < static_cast<int>(list->genericGetSize()));
}
bool SlicingSearch::isIndexValid(std::vector<SearchState *> &list, int index) {
    return (direction < 0 ? index >= 0
            : index < static_cast<int>(list.size()));
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

        LOG(11, "visit " << node->getDescription());

        // visit all prior instructions in this node in forwards/backwards order
        bool stillSearching = true;
        auto insList = node->getBlock()->getChildren();
        for(int index = insList->getIterable()->indexOf(instruction);
            isIndexValid(insList, index);
            index += direction) {

            Instruction *i = insList->getIterable()->get(index);

            currentState->setInstruction(i);

            stillSearching = false;
            for(auto r : currentState->getRegs()) {
                if(r) {
                    stillSearching = true;
                    break;
                }
            }
            if(!stillSearching) break;

            buildStateFor(currentState);
            stateList.push_back(currentState);

            if(isIndexValid(insList, index+direction)) {
                auto newState = new SearchState(*currentState);
                currentState->addParent(newState);
                currentState = newState;
            }
        }

        if(stillSearching) {
            // find all nodes that link to this one, keep searching there
            for(auto link : node->backwardLinks()) {
                auto newNode = cfg->get(link.getID());
                if(!visited[newNode->getID()]) {
                    auto offset = link.getOffset();
                    Instruction *newStart
                        = newNode->getBlock()->getChildren()->getSpatial()->find(
                            newNode->getBlock()->getAddress() + offset);
                    LOG(11, "    start at offset " << offset << " -> " << newStart);
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
}

void SlicingSearch::buildRegTreePass() {
    LOG(11, "second pass iteration");
    int index = (direction < 0 ? stateList.size() - 1 : 0);
    for(; isIndexValid(stateList, index); index += direction) {
        auto state = stateList[index];
        auto instruction = state->getInstruction();

        SlicingUtilities u;
        u.printRegs(state, false);
        //ChunkDumper dumper;
        //dumper.visit(instruction);

        u.copyParentMemTrees(state);
        buildRegTreesFor(state);
        u.copyParentRegTrees(state);  // inherit interesting regs from parent
        u.printRegTrees(state);
        u.printMemTrees(state);
        if(halt && halt->cutoff(state)) {
            break;
        }
    }
}

void SlicingSearch::debugPrintRegAccesses(Instruction *i) {
    auto assembly = i->getSemantic()->getAssembly();
    if(!assembly) return;

    SlicingUtilities u;

    for(size_t r = 0; r < assembly->getImplicitRegsReadCount(); r ++) {
        LOG(11, "        implicit reg read "
            << u.printReg(assembly->getImplicitRegsRead()[r]));
    }
    for(size_t r = 0; r < assembly->getImplicitRegsWriteCount(); r ++) {
        LOG(11, "        implicit reg write "
            << u.printReg(assembly->getImplicitRegsWrite()[r]));
    }

    auto asmOps = assembly->getAsmOperands();
    for(size_t p = 0; p < asmOps->getOpCount(); p ++) {
        auto op = &asmOps->getOperands()[p];  // cs_x86_op*, cs_arm64_op*
        if(static_cast<cs_op_type>(op->type) == CS_OP_REG) {
            LOG(11, "        explicit reg ref "
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
        // AARCH64 cases have nothing in common?
        MODE_REG_REG_REG,
        MODE_REG_IMM,
        MODE_REG_MEM,
        MODE_REG_REG_IMM,
        MODE_REG_REG_MEM,
    };
private:
    SearchState *state;
    Mode mode;
#ifdef ARCH_X86_64
    union arg1_t {
        x86_reg reg;
        const x86_op_mem *mem;
        unsigned long imm;
    } a1;
    union arg2_t {
        x86_reg reg;
    } a2;
    union arg3_t {
    } a3;
#elif defined(ARCH_AARCH64)
    typedef struct extmem {
        const arm64_op_mem *mem;
        arm64_extender ext;
        struct {
            arm64_shifter type;
            unsigned int value;
        } shift;
    } extmem_t;
    typedef struct extreg {
        arm64_reg reg;
        arm64_extender ext;
        struct {
            arm64_shifter type;
            unsigned int value;
        } shift;
    } extreg_t;
    typedef struct extimm {
        int64_t imm;
        struct {
            arm64_shifter type;
            unsigned int value;
        } shift;
    } extimm_t;

    union arg1_t {
        arm64_reg reg;
        int64_t imm;
    } a1;
    union arg2_t {
        arm64_reg reg;
        int64_t imm;
        extmem_t extmem;
    } a2;
    union arg3_t {
        extreg_t extreg;
        extimm_t extimm;
        const arm64_op_mem *mem;
    } a3;
#endif
public:
    SlicingInstructionState(SearchState *state, Assembly *assembly)
        : state(state) { determineMode(assembly); }

    arg1_t *get1() { return &a1; }
    arg2_t *get2() { return &a2; }
    arg3_t *get3() { return &a3; }
    Mode getMode() const { return mode; }

    void defaultDetectRegReg(bool overwriteTarget);
    void defaultDetectMemReg(bool overwriteTarget);
    void defaultDetectImmReg(bool overwriteTarget);

    void defaultDetectRegRegReg(bool overwriteTarget);
    void defaultDetectRegImm(bool overwriteTarget);
    void defaultDetectRegMem(bool overwriteTarget);
    void defaultDetectRegRegImm(bool overwriteTarget);
    void defaultDetectRegRegMem(bool overwriteTarget);
private:
    void determineMode(Assembly *assembly);
    bool convertRegisterSize(Register &reg);
};

SearchState::~SearchState() {
    delete iState;
}


void SlicingInstructionState::determineMode(Assembly *assembly) {
    mode = MODE_UNKNOWN;
    auto asmOps = assembly->getAsmOperands();
#ifdef ARCH_X86_64
    if(asmOps->getOpCount()== 2
        && asmOps->getOperands()[0].type == X86_OP_REG
        && asmOps->getOperands()[1].type == X86_OP_REG) {

        mode = MODE_REG_REG;
        a1.reg = asmOps->getOperands()[0].reg;
        a2.reg = asmOps->getOperands()[1].reg;
    }
    if(asmOps->getOpCount() == 2
        && asmOps->getOperands()[0].type == X86_OP_MEM
        && asmOps->getOperands()[1].type == X86_OP_REG) {

        mode = MODE_MEM_REG;
        a1.mem = &asmOps->getOperands()[0].mem;
        a2.reg = asmOps->getOperands()[1].reg;
    }
    if(asmOps->getOpCount() == 2
        && asmOps->getOperands()[0].type == X86_OP_IMM
        && asmOps->getOperands()[1].type == X86_OP_REG) {

        mode = MODE_IMM_REG;
        a1.imm = asmOps->getOperands()[0].imm;
        a2.reg = asmOps->getOperands()[1].reg;
    }
#elif defined(ARCH_AARCH64)
    if(asmOps->getOpCount() == 2) {
        if(asmOps->getOperands()[0].type == ARM64_OP_REG
           && asmOps->getOperands()[1].type == ARM64_OP_REG) {

            mode = MODE_REG_REG;
            a1.reg = static_cast<arm64_reg>(asmOps->getOperands()[0].reg);
            a2.reg = static_cast<arm64_reg>(asmOps->getOperands()[1].reg);
        }
        else if(asmOps->getOperands()[0].type == ARM64_OP_REG
           && asmOps->getOperands()[1].type == ARM64_OP_IMM) {

            mode = MODE_REG_IMM;
            a1.reg = static_cast<arm64_reg>(asmOps->getOperands()[0].reg);
            a2.imm = asmOps->getOperands()[1].imm;
        }
        else if(asmOps->getOperands()[0].type == ARM64_OP_REG
           && asmOps->getOperands()[1].type == ARM64_OP_MEM) {

            mode = MODE_REG_MEM;
            a1.reg = static_cast<arm64_reg>(asmOps->getOperands()[0].reg);
            a2.extmem.mem = &asmOps->getOperands()[1].mem;
            a2.extmem.ext = asmOps->getOperands()[1].ext;
            a2.extmem.shift.type = asmOps->getOperands()[1].shift.type;
            a2.extmem.shift.value = asmOps->getOperands()[1].shift.value;
        }
    }
    else if(asmOps->getOpCount() == 3) {
        if(asmOps->getOperands()[0].type == ARM64_OP_REG
           && asmOps->getOperands()[1].type == ARM64_OP_REG
           && asmOps->getOperands()[2].type == ARM64_OP_REG) {

            mode = MODE_REG_REG_REG;
            a1.reg = static_cast<arm64_reg>(asmOps->getOperands()[0].reg);
            a2.reg = static_cast<arm64_reg>(asmOps->getOperands()[1].reg);
            a3.extreg.reg = static_cast<arm64_reg>(
                asmOps->getOperands()[2].reg);
            a3.extreg.ext = asmOps->getOperands()[2].ext;
            a3.extreg.shift.type = asmOps->getOperands()[2].shift.type;
            a3.extreg.shift.value = asmOps->getOperands()[2].shift.value;
        }
        else if(asmOps->getOperands()[0].type == ARM64_OP_REG
                && asmOps->getOperands()[1].type == ARM64_OP_REG
                && asmOps->getOperands()[2].type == ARM64_OP_IMM) {
            mode = MODE_REG_REG_IMM;
            a1.reg = static_cast<arm64_reg>(asmOps->getOperands()[0].reg);
            a2.reg = static_cast<arm64_reg>(asmOps->getOperands()[1].reg);
            a3.extimm.imm = asmOps->getOperands()[2].imm;
            a3.extimm.shift.type = asmOps->getOperands()[2].shift.type;
            a3.extimm.shift.value = asmOps->getOperands()[2].shift.value;
        }
        else if(asmOps->getOperands()[0].type == ARM64_OP_REG
                && asmOps->getOperands()[1].type == ARM64_OP_REG
                && asmOps->getOperands()[2].type == ARM64_OP_MEM) {
            mode = MODE_REG_REG_MEM;
            a1.reg = static_cast<arm64_reg>(asmOps->getOperands()[0].reg);
            a2.reg = static_cast<arm64_reg>(asmOps->getOperands()[1].reg);
            a3.mem = &asmOps->getOperands()[2].mem;
        }
    }
#endif
}

bool SlicingInstructionState::convertRegisterSize(Register &reg) {
    if(state->getReg(reg)) {
        return false;  // We are already looking for this exact register
    }

#if defined(ARCH_X86_64)
    static const Register promotion[][4] = {
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
#elif defined(ARCH_AARCH64)
    static const Register promotion[][2] = {
        {ARM64_REG_W0,  ARM64_REG_X0},
        {ARM64_REG_W1,  ARM64_REG_X1},
        {ARM64_REG_W2,  ARM64_REG_X2},
        {ARM64_REG_W3,  ARM64_REG_X3},
        {ARM64_REG_W4,  ARM64_REG_X4},
        {ARM64_REG_W5,  ARM64_REG_X5},
        {ARM64_REG_W6,  ARM64_REG_X6},
        {ARM64_REG_W7,  ARM64_REG_X7},
        {ARM64_REG_W8,  ARM64_REG_X8},
        {ARM64_REG_W9,  ARM64_REG_X9},
        {ARM64_REG_W10, ARM64_REG_X10},
        {ARM64_REG_W11, ARM64_REG_X11},
        {ARM64_REG_W12, ARM64_REG_X12},
        {ARM64_REG_W13, ARM64_REG_X13},
        {ARM64_REG_W14, ARM64_REG_X14},
        {ARM64_REG_W15, ARM64_REG_X15},
        {ARM64_REG_W16, ARM64_REG_X16},
        {ARM64_REG_W17, ARM64_REG_X17},
        {ARM64_REG_W18, ARM64_REG_X18},
        {ARM64_REG_W19, ARM64_REG_X19},
        {ARM64_REG_W20, ARM64_REG_X20},
        {ARM64_REG_W21, ARM64_REG_X21},
        {ARM64_REG_W22, ARM64_REG_X22},
        {ARM64_REG_W23, ARM64_REG_X23},
        {ARM64_REG_W24, ARM64_REG_X24},
        {ARM64_REG_W25, ARM64_REG_X25},
        {ARM64_REG_W26, ARM64_REG_X26},
        {ARM64_REG_W27, ARM64_REG_X27},
        {ARM64_REG_W28, ARM64_REG_X28},
        {ARM64_REG_W29, ARM64_REG_X29},
        {ARM64_REG_W30, ARM64_REG_X30},
    };
#endif

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
#ifdef ARCH_X86_64
    convertRegisterSize(a2.reg);
    auto source = a1.reg;
    auto target = a2.reg;

    if(state->getReg(target)) {
        state->addReg(source);
        if(overwriteTarget) {
            state->removeReg(target);
        }
    }
#elif defined(ARCH_AARCH64)
    convertRegisterSize(a1.reg);
    auto target = a1.reg;
    auto source = a2.reg;

    if(state->getReg(target)) {
        state->addReg(source);
        if(overwriteTarget) {
            state->removeReg(target);
        }
    }
#endif
}
void SlicingInstructionState::defaultDetectMemReg(bool overwriteTarget) {
#ifdef ARCH_X86_64
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
#elif defined(ARCH_AARCH64)
    throw "not implemented";
#endif
}
void SlicingInstructionState::defaultDetectImmReg(bool overwriteTarget) {
#ifdef ARCH_X86_64
    convertRegisterSize(a2.reg);
    //auto imm = a1.imm;
    auto reg = a2.reg;

    if(state->getReg(reg)) {
        if(overwriteTarget) {
            state->removeReg(reg);
        }
    }
#elif defined(ARCH_AARCH64)
    throw "not implemented";
#endif
}
// if we use getTargetReg(), getSourceReg1(), getSourceReg2(), ...
// also the body of function seems to be 1:1 mapping against the type
void SlicingInstructionState::defaultDetectRegRegReg(bool overwriteTarget) {
#ifdef ARCH_X86_64
#elif defined(ARCH_AARCH64)
    convertRegisterSize(a1.reg);
    auto target = a1.reg;
    auto source1 = a2.reg;
    auto source2 = a3.extreg.reg;

    if(state->getReg(target)) {
        if(overwriteTarget) {
            state->removeReg(target);
        }
        // re-add if target == source1 or source2
        state->addReg(source1);
        state->addReg(source2);
    }
#endif
}
void SlicingInstructionState::defaultDetectRegImm(bool overwriteTarget) {
#ifdef ARCH_X86_64
#elif defined(ARCH_AARCH64)
    convertRegisterSize(a1.reg);
    //auto imm = a2.imm;
    auto reg = a1.reg;

    if(state->getReg(reg)) {
        state->addReg(reg);
        if(overwriteTarget) {
            state->removeReg(reg);
        }
    }
#endif
}

void SlicingInstructionState::defaultDetectRegMem(bool overwriteTarget) {
#ifdef ARCH_X86_64
#elif defined(ARCH_AARCH64)
    convertRegisterSize(a1.reg);
    auto reg = a1.reg;
    auto extmem = a2.extmem;

    if(state->getReg(reg)) {
        if(overwriteTarget) {
            state->removeReg(reg);
        }
        state->addReg(extmem.mem->base);
        if(extmem.mem->index != INVALID_REGISTER) {
            state->addReg(extmem.mem->index);
        }
    }
#endif
}
void SlicingInstructionState::defaultDetectRegRegImm(bool overwriteTarget) {
#ifdef ARCH_X86_64
#elif defined(ARCH_AARCH64)
    convertRegisterSize(a1.reg);
    auto target = a1.reg;
    auto source = a2.reg;
    //auto imm = a3.imm;

    if(state->getReg(target)) {
        if(overwriteTarget) {
            state->removeReg(target);
        }
        // re-add if target == source
        state->addReg(source);
    }
#endif
}
void SlicingInstructionState::defaultDetectRegRegMem(bool overwriteTarget) {
#ifdef ARCH_X86_64
#elif defined(ARCH_AARCH64)
    convertRegisterSize(a1.reg);
    auto target = a1.reg;
    auto source = a2.reg;
    auto mem = a3.mem;

    if(state->getReg(target)) {
        if(overwriteTarget) {
            state->removeReg(target);
        }
        // re-add if target == source
        state->addReg(source);
        if(mem->base != INVALID_REGISTER) {
            state->addReg(mem->base);
        }
        if(mem->index != INVALID_REGISTER) {
            state->addReg(mem->index);
        }
    }
#endif
}

void SlicingSearch::buildStateFor(SearchState *state) {
    auto assembly = state->getInstruction()->getSemantic()->getAssembly();

    debugPrintRegAccesses(state->getInstruction());

    detectInstruction(state, true);

    if(assembly) {
        // if any instruction overwrites condition flags, remove from reg set
        for(size_t r = 0; r < assembly->getImplicitRegsWriteCount(); r ++) {
            if(assembly->getImplicitRegsWrite()[r] == CONDITION_REGISTER) {
                state->removeReg(CONDITION_REGISTER);
            }
        }
    }

#ifdef ARCH_X86_64
    state->removeReg(X86_REG_RIP);  // never care about this
#endif
}

void SlicingSearch::buildRegTreesFor(SearchState *state) {
    detectInstruction(state, false);
}

void SlicingSearch::detectInstruction(SearchState *state, bool firstPass) {
    auto assembly = state->getInstruction()->getSemantic()->getAssembly();
#ifdef ARCH_X86_64
    if(!assembly) {
#elif defined(ARCH_AARCH64)
    if(dynamic_cast<ControlFlowInstruction *>(
        state->getInstruction()->getSemantic())) {

#endif
        detectJumpRegTrees(state, firstPass);
        return;
    }

    SlicingUtilities u;

    SlicingInstructionState *iState;
    if(firstPass) {
        iState = new SlicingInstructionState(state, assembly);
        state->setIState(iState);
    }
    else {
        iState = state->getIState();
    }
    auto mode = iState->getMode();

    switch(assembly->getId()) {
#ifdef ARCH_X86_64
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
        LOG(11, "        add found");
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
        LOG(11, "        lea found");
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
        LOG(11, "        mov found");
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

        LOG(11, "        movslq found");
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
        LOG(11, "        movzx found");
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
#elif defined(ARCH_AARCH64)
    case ARM64_INS_MOV:
        if(mode == SlicingInstructionState::MODE_REG_REG) {
            if(firstPass) {
                iState->defaultDetectRegReg(true);
            }
            else {
                auto target = iState->get1()->reg;
                auto source = iState->get2()->reg;

                state->setRegTree(target, u.getParentRegTree(state, source));
            }
        }
        else {
            LOG(11, "unknown mode for mov" << mode);
        }
        LOG(11, "        mov found");
        break;
#if 1
    case ARM64_INS_MOVZ:
        LOG(11, "        movz found -- ignored");
        break;
#endif
    case ARM64_INS_ADRP:
        if(mode == SlicingInstructionState::MODE_REG_IMM) {
            if(firstPass) {
                iState->defaultDetectRegImm(true);
            }
            else {
                auto reg = iState->get1()->reg;
                auto imm = iState->get2()->imm;

                state->setRegTree(reg, new TreeNodeAddress(imm));
            }
        }
        else {
            LOG(11, "unknown mode for adrp");
        }
        LOG(11, "        adrp found");
        break;
    case ARM64_INS_ADR:
        if(mode == SlicingInstructionState::MODE_REG_IMM) {
            if(firstPass) {
                iState->defaultDetectRegImm(true);
            }
            else {
                auto reg = iState->get1()->reg;
                auto imm = iState->get2()->imm; //cs adds PC internally

                state->setRegTree(reg, new TreeNodeAddress(imm));
            }
        }
        else {
            LOG(11, "unknown mode for adr");
        }
        LOG(11, "        adr found");
        break;
    case ARM64_INS_ADD:
        if(mode == SlicingInstructionState::MODE_REG_REG_REG) {
            if(firstPass) {
                iState->defaultDetectRegRegReg(true);
            }
            else {
                auto target = iState->get1()->reg;
                auto source1 = iState->get2()->reg;
                auto *extreg = &iState->get3()->extreg;
                auto source2 = extreg->reg;

                TreeNode *tree = u.getParentRegTree(state, source2);
#if 0
                if(extreg->ext != ARM64_EXT_INVALID) {
                    if(extreg->ext == ARM64_EXT_SXTW) {
                        tree = new TreeNodeSignExtendWord(tree);
                    }
                    else if(extreg->ext == ARM64_EXT_SXTH) {
                        tree = new TreeNodeSignExtendHalfWord(tree);
                    }
                    else if(extreg->ext == ARM64_EXT_SXTB) {
                        tree = new TreeNodeSignExtendByte(tree);
                    }
                    else {
                        LOG(11, "unknown extender");
                    }
                }
#endif
                if(extreg->shift.type != ARM64_SFT_INVALID) {
                    if(extreg->shift.type == ARM64_SFT_LSL) {
                        tree = new TreeNodeLogicalShiftLeft(tree,
                            new TreeNodeConstant(extreg->shift.value));
                    }
                }

                state->setRegTree(target, new TreeNodeAddition(
                    u.getParentRegTree(state, source1),
                    tree));
            }
        }
        else if(mode == SlicingInstructionState::MODE_REG_REG_IMM) {
            if(firstPass) {
                iState->defaultDetectRegRegImm(true);
            }
            else {
                auto target = iState->get1()->reg;
                auto source = iState->get2()->reg;
                auto extimm = iState->get3()->extimm;
                auto imm = extimm.imm;

                TreeNode *tree = nullptr;
                if(extimm.shift.type != ARM64_SFT_INVALID) {
                    if(extimm.shift.type == ARM64_SFT_LSL) {
                        imm = imm << extimm.shift.value;
                    }
                }

                auto parent_source = u.getParentRegTree(state, source);
                if(auto p = dynamic_cast<TreeNodeConstant *>(parent_source)) {
                    p->setValue(p->getValue() + extimm.imm);
                    state->setRegTree(target, p);
                }
                else if(auto p = dynamic_cast<TreeNodeAddress *>(parent_source)) {
                    p->setValue(p->getValue() + extimm.imm);
                    state->setRegTree(target, p);
                }
                else {
                    tree = new TreeNodeConstant(extimm.imm);

                    state->setRegTree(target, new TreeNodeAddition(
                        u.getParentRegTree(state, source),
                        tree));
                }
            }
        }
        else {
            LOG(11, "unknown mode for add");
        }
        LOG(11, "        add found");
        break;
    case ARM64_INS_SUB:
        if(mode == SlicingInstructionState::MODE_REG_REG_IMM) {
            if(firstPass) {
                iState->defaultDetectRegRegImm(true);
            }
            else {
                auto target = iState->get1()->reg;
                auto source = iState->get2()->reg;
                auto extimm = iState->get3()->extimm;

                TreeNode *tree = new TreeNodeConstant(extimm.imm);
                if(extimm.shift.type != ARM64_SFT_INVALID) {
                    if(extimm.shift.type == ARM64_SFT_LSL) {
                        tree = new TreeNodeLogicalShiftLeft(tree,
                            new TreeNodeConstant(extimm.shift.value));
                    }
                }

                state->setRegTree(target, new TreeNodeSubtraction(
                    u.getParentRegTree(state, source),
                    tree));
            }
        }
        else if(mode == SlicingInstructionState::MODE_REG_REG_REG) {
            if(firstPass) {
                iState->defaultDetectRegRegReg(true);
            }
            else {
                auto target = iState->get1()->reg;
                auto source1 = iState->get2()->reg;
                auto *extreg = &iState->get3()->extreg;
                auto source2 = extreg->reg;

                TreeNode *tree = u.getParentRegTree(state, source2);
                if(extreg->shift.type != ARM64_SFT_INVALID) {
                    if(extreg->shift.type == ARM64_SFT_LSL) {
                        tree = new TreeNodeLogicalShiftLeft(tree,
                            new TreeNodeConstant(extreg->shift.value));
                    }
                }

                state->setRegTree(target, new TreeNodeSubtraction(
                    u.getParentRegTree(state, source1),
                    tree));
            }
        }
        else {
            LOG(11, "unknown mode for sub");
        }
        LOG(11, "        sub found");
        break;
    case ARM64_INS_LDR:
    case ARM64_INS_LDRH:
    case ARM64_INS_LDRB:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDRSW:
        if(mode == SlicingInstructionState::MODE_REG_MEM) {
            if(firstPass) {
                iState->defaultDetectRegMem(true);
            }
            else {
                auto reg = iState->get1()->reg;
                auto extmem = iState->get2()->extmem;

                auto tree = u.makeMemTree(state, extmem.mem, extmem.ext,
                                          extmem.shift.type, extmem.shift.value);
                state->setRegTree(reg, tree);
            }
        }
        else {
            LOG(11, "unknown mode for ldr(h|b|sb|sh|sw)");
        }
        LOG(11, "        ldr(h|b|sb|sh|sw) found");
        break;
    case ARM64_INS_STR:
    case ARM64_INS_STRH:
    case ARM64_INS_STRB:
        if(mode == SlicingInstructionState::MODE_REG_MEM) {
            if(firstPass) {
                iState->defaultDetectRegMem(false);
            }
            else {
                auto reg = iState->get1()->reg;
                auto extmem = iState->get2()->extmem;

                auto tree = u.makeMemTree(state, extmem.mem, extmem.ext,
                                          extmem.shift.type, extmem.shift.value);

                state->addMemTree(tree, u.getParentRegTree(state, reg));
            }
        }
        else {
            LOG(11, "unknown mode for str(h|b)");
        }
        LOG(11, "        str(h|b) found");
        break;
    case ARM64_INS_CMP:
        if(mode == SlicingInstructionState::MODE_REG_IMM) {
            if(firstPass) {
                iState->defaultDetectRegImm(false);
            }
            else {
                auto reg = iState->get1()->reg;
                auto imm = iState->get2()->imm;
                state->setRegTree(ARM64_REG_NZCV,
                    new TreeNodeComparison(
                        u.getParentRegTree(state, reg),
                        new TreeNodeConstant(imm)));
            }
        }
        else if(mode == SlicingInstructionState::MODE_REG_REG) {
            if(firstPass) {
                iState->defaultDetectRegReg(false);
            }
            else {
                auto reg1 = iState->get1()->reg;
                auto reg2 = iState->get2()->reg;
                state->setRegTree(ARM64_REG_NZCV,
                    new TreeNodeComparison(
                        u.getParentRegTree(state, reg1),
                        u.getParentRegTree(state, reg2)));
            }

        }
        else {
            LOG(11, "unknown mode for cmp");
        }
        LOG(11, "        cmp found");
        break;
    case ARM64_INS_CCMP:
        LOG(11, "        ccmp found -- HANDLER NOT YET IMPLEMENTED");
        break;
    case ARM64_INS_TST:
        LOG(11, "        tst found -- HANDLER NOT YET IMPLEMENTED");
        break;
#endif
    default:
        LOG(11, "        got instr id " << assembly->getId()
            << "(" << assembly->getMnemonic() << ")");
        break;
    }
}

void SlicingSearch::detectJumpRegTrees(SearchState *state, bool firstPass) {
    SlicingUtilities u;
    auto semantic = state->getInstruction()->getSemantic();
    LOG(11, "@ " << std::hex << state->getInstruction()->getAddress());
    if(auto v = dynamic_cast<ControlFlowInstruction *>(semantic)) {
#ifdef ARCH_X86_64
        if(v->getMnemonic() != "jmp" && v->getMnemonic() != "callq") {
#elif defined(ARCH_AARCH64)
        if(v->getMnemonic() != "b" && v->getMnemonic() != "bl") {
#endif
            if(firstPass) {
                state->addReg(CONDITION_REGISTER);
            }
            else {
                LOG0(11, "    found a conditional jump, condition is ");
                //auto tree = state->getRegTree(CONDITION_REGISTER);
                auto tree = u.getParentRegTree(state, CONDITION_REGISTER);
                if(tree) {
                    IF_LOG(11) tree->print(TreePrinter(2, 0));
                }
                else LOG0(11, "NULL");
                LOG(11, "");

                state->setRegTree(CONDITION_REGISTER, tree);

                conditions.push_back(state);
            }
        }
    }
}

