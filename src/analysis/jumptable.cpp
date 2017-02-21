#include <iostream>
#include <sstream>
#include <string>
#include <map>
#include <iomanip>  // for std::setw, std::hex
#include <utility>
#include <capstone/capstone.h>
#include "jumptable.h"
#include "controlflow.h"
#include "chunk/instruction.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"

#include "types.h"
#include "log/log.h"

class SearchState;

class TreePrinter {
private:
    int _indent;
    int _splits;
public:
    TreePrinter(int _indent = 1, int _splits = 2)
        : _indent(_indent), _splits(_splits) {}

    TreePrinter nest() const { return TreePrinter(_indent + 1, _splits - 1); }
    std::ostream &stream() const { return std::cout; }
    void indent() const { stream() << std::string(4*_indent, ' '); }
    bool shouldSplit() const { return _splits > 0; }
};

class TreeNode {
public:
    virtual ~TreeNode() {}
    virtual void print(const TreePrinter &p) const = 0;
};

class TreeNodeConstant : public TreeNode {
private:
    unsigned long value;
public:
    TreeNodeConstant(unsigned long value) : value(value) {}
    virtual void print(const TreePrinter &p) const
        { p.stream() << value; }
};

class TreeNodeAddress : public TreeNode {
private:
    address_t address;
public:
    TreeNodeAddress(address_t address) : address(address) {}
    virtual void print(const TreePrinter &p) const
        { p.stream() << "0x" << std::hex << address; }
};

class TreeNodeRegister : public TreeNode {
private:
    Register reg;
public:
    TreeNodeRegister(int reg) : reg(Register(reg)) {}
    virtual void print(const TreePrinter &p) const
        { Disassemble::Handle h(true); p.stream() << "%" << cs_reg_name(h.raw(), reg); }
};

class TreeNodeUnary : public TreeNode {
private:
    TreeNode *node;
    const char *name;
public:
    TreeNodeUnary(TreeNode *node, const char *name)
        : node(node), name(name) {}
    virtual void print(const TreePrinter &p) const;
};

void TreeNodeUnary::print(const TreePrinter &p) const {
    p.stream() << "(" << name << " ";
    node->print(p);
    p.stream() << ")";
}

class TreeNodeDereference : public TreeNodeUnary {
public:
    TreeNodeDereference(TreeNode *node)
        : TreeNodeUnary(node, "deref") {}
};
class TreeNodeJump : public TreeNodeUnary {
public:
    TreeNodeJump(TreeNode *node)
        : TreeNodeUnary(node, "jump") {}
};

class TreeNodeBinary : public TreeNode {
private:
    TreeNode *left;
    TreeNode *right;
    const char *op;
public:
    TreeNodeBinary(TreeNode *left, TreeNode *right, const char *op)
        : left(left), right(right), op(op) {}
    TreeNode *getLeft() const { return left; }
    TreeNode *getRight() const { return left; }
    const char *getOperator() const { return op; }

    virtual void print(const TreePrinter &p) const;
};

void TreeNodeBinary::print(const TreePrinter &p) const {
    if(p.shouldSplit()) {
        p.stream() << "(" << op << "\n";
        p.indent();
        left->print(p.nest());
        p.stream() << "\n";
        p.indent();
        right->print(p.nest());
        p.stream() << ")";
    }
    else {
        p.stream() << "(" << op << " ";
        left->print(p);
        p.stream() << " ";
        right->print(p);
        p.stream () << ")";
    }
}

class TreeNodeAddition : public TreeNodeBinary {
public:
    TreeNodeAddition(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "+") {}
};
class TreeNodeMultiplication : public TreeNodeBinary {
public:
    TreeNodeMultiplication(TreeNode *left, TreeNode *right)
        : TreeNodeBinary(left, right, "*") {}
};

#if 0
template <typename SpecificType>
class TreePatternSpecificType {
public:
    bool matches(TreeNode *node) const
        { return dynamic_cast<SpecificType *>(node) != nullptr; }
};

class TreePatternAny {
public:
    bool matches(TreeNode *node) const { return true; }
};
#endif

class SearchState {
private:
    ControlFlowNode *node;
    Instruction *instruction;
    std::vector<bool> regs;
    std::vector<SearchState *> parents;
    std::map<int, TreeNode *> regTree;
public:
    SearchState() : node(nullptr), instruction(nullptr) {}
    SearchState(ControlFlowNode *node, Instruction *instruction)
        : node(node), instruction(instruction), regs(X86_REG_ENDING) {}
    SearchState(const SearchState &other)
        : node(other.node), instruction(other.instruction), regs(other.regs) {}

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
    void setRegTree(int reg, TreeNode *tree) { regTree[reg] = tree; }
};

TreeNode *SearchState::getRegTree(int reg) {
    auto it = regTree.find(reg);
    return (it != regTree.end() ? (*it).second : nullptr);
}

class SearchHelper {
private:
    Disassemble::Handle handle;
private:
    ControlFlowGraph *cfg;
    std::vector<bool> visited;  // indexed by ControlFlowNode ID
    std::vector<SearchState *> stateList;  // history of states
    std::vector<SearchState *> transitionList;  // new states (BFS)
    SearchState *currentState;  // current, not in stateList or transitionList
public:
    SearchHelper(ControlFlowGraph *cfg)
        : handle(true), cfg(cfg), visited(cfg->getCount()),
        currentState(nullptr) {}
    void init(Instruction *i);

    void run();
    void secondPass();
private:
    void visitInstruction(Instruction *i);
    const char *printReg(int reg);
    void printRegs(SearchState *state, bool withNewline = true);
    void printRegTrees(SearchState *state);
    void copyParentRegTrees(SearchState *state);
    TreeNode *makeMemTree(SearchState *state, x86_op_mem *mem);
    TreeNode *getParentRegTree(SearchState *state, int reg);
    void handleKnownInstruction(SearchState *state);
};

void SearchHelper::init(Instruction *i) {
    auto j = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic());
    auto block = dynamic_cast<Block *>(i->getParent());
    auto node = cfg->get(block);
    LOG(1, "search for jump table at " << i->getName());

    SearchState *startState = new SearchState(node, i);
    startState->addReg(j->getRegister());
    transitionList.push_back(startState);
}

void SearchHelper::run() {
    while(transitionList.size() > 0) {
        this->currentState = transitionList.front();
        transitionList.erase(transitionList.begin());
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

            visitInstruction(i);
            stateList.push_back(currentState);

            if(index > 0) {
                auto newState = new SearchState(*currentState);
                currentState->addParent(newState);
                currentState = newState;
            }
        }

        // find all nodes that link to this one, keep searching there
        for(auto link : node->backwardLinks()) {
            auto newNode = cfg->get(link.first);
            if(!visited[newNode->getID()]) {
                auto offset = link.second;
                Instruction *newStart
                    = newNode->getBlock()->getChildren()->getSpatial()->find(
                        newNode->getBlock()->getAddress() + offset);
                LOG(1, "    start at offset " << offset << " -> " << newStart);
                SearchState *newState = new SearchState(*currentState);
                newState->setNode(newNode);
                newState->setInstruction(newStart);
                transitionList.push_back(newState);
                currentState->addParent(newState);
            }
        }
    }
}

void SearchHelper::visitInstruction(Instruction *i) {
    auto capstone = i->getSemantic()->getCapstone();
    if(!capstone) return;
    auto detail = capstone->detail;
    if(!detail) return;

    for(size_t r = 0; r < detail->regs_read_count; r ++) {
        LOG(1, "        implicit reg read "
            << printReg(detail->regs_read[r]));
    }
    for(size_t r = 0; r < detail->regs_write_count; r ++) {
        LOG(1, "        implicit reg write "
            << printReg(detail->regs_write[r]));
    }

#ifdef ARCH_X86_64
    cs_x86 *x = &capstone->detail->x86;
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &capstone->detail->arm64;
#endif
    for(size_t p = 0; p < x->op_count; p ++) {
        auto op = &x->operands[p];  // cs_x86_op*, cs_arm64_op*
        if(static_cast<cs_op_type>(op->type) == CS_OP_REG) {
            LOG(1, "        explicit reg ref "
                << printReg(op->reg));
            //currentState->addReg(op->reg);
        }
    }


    static bool knownInstruction[X86_INS_ENDING] = {};
    knownInstruction[X86_INS_ADD] = true;
    knownInstruction[X86_INS_LEA] = true;
    knownInstruction[X86_INS_MOVSXD] = true;

    if(knownInstruction[capstone->id]) {
        if(x->op_count == 2
            && x->operands[0].type == X86_OP_REG
            && x->operands[1].type == X86_OP_REG) {

            auto source = x->operands[0].reg;
            auto target = x->operands[1].reg;

            if(currentState->getReg(target)) {
                currentState->addReg(source);
                currentState->addReg(target);
            }
        }
        if(x->op_count == 2
            && x->operands[0].type == X86_OP_MEM
            && x->operands[1].type == X86_OP_REG) {

            auto mem = &x->operands[0].mem;
            auto out = x->operands[1].reg;

            if(currentState->getReg(out)) {
                currentState->removeReg(out);
                if(mem->base != X86_REG_INVALID) {
                    currentState->addReg(mem->base);
                }
                if(mem->index != X86_REG_INVALID) {
                    currentState->addReg(mem->index);
                }
            }
        }
    }

    currentState->removeReg(X86_REG_RIP);  // never care about this
}

void SearchHelper::secondPass() {
    LOG(1, "second pass iteration");
    for(auto it = stateList.rbegin(); it != stateList.rend(); ++it) {
        auto state = (*it);
        auto instruction = state->getInstruction();

        printRegs(state, false);
        ChunkDumper dumper;
        dumper.visit(instruction);

        handleKnownInstruction(state);
        copyParentRegTrees(state);
        printRegTrees(state);
    }
}

const char *SearchHelper::printReg(int reg) {
    return cs_reg_name(handle.raw(), reg);
}

void SearchHelper::printRegs(SearchState *state, bool withNewline) {
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

void SearchHelper::printRegTrees(SearchState *state) {
    const auto &regs = state->getRegs();
    for(size_t r = 0; r < regs.size(); r ++) {
        auto tree = state->getRegTree(r);
        if(!tree) continue;

        std::cout << "        REG " << printReg(r) << ": ";
        tree->print(TreePrinter(3, 1));
        std::cout << "\n";
    }
}

void SearchHelper::copyParentRegTrees(SearchState *state) {
    const auto &parents = state->getParents();
    if(parents.size() == 0) {
        const auto &regs = state->getRegs();
        for(size_t r = 0; r < regs.size(); r ++) {
            if(regs[r] && !state->getRegTree(r)) {
                LOG(1, "    set reg tree");
                state->setRegTree(r, new TreeNodeRegister(r));
            }
        }
    }
    else if(parents.size() == 1) {
        auto parent = parents.front();
        const auto &regs = state->getRegs();
        for(size_t r = 0; r < regs.size(); r ++) {
            if(!regs[r]) continue;

            // see if this tree was already set by handleKnownInstruction
            if(state->getRegTree(r)) continue;

            auto tree = parent->getRegTree(r);
            if(!tree) tree = new TreeNodeRegister(r);
            state->setRegTree(r, tree);
        }
    }
    else {
        LOG(1, "    multiple parents not yet implemented!");
    }
}

TreeNode *SearchHelper::makeMemTree(SearchState *state, x86_op_mem *mem) {
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
    if(tree) {
        tree = new TreeNodeAddition(baseTree, tree);
    }
    else if(mem->base != X86_REG_INVALID) {
        tree = baseTree;
    }

    if(mem->disp) {
        tree = new TreeNodeAddition(
            new TreeNodeAddress(mem->disp), tree);
    }

    return tree;
}

TreeNode *SearchHelper::getParentRegTree(SearchState *state, int reg) {
    const auto &parents = state->getParents();
    if(parents.size() == 0) {
        return new TreeNodeRegister(reg);
    }
    else if(parents.size() == 1) {
        auto tree = parents.front()->getRegTree(reg);
        if(!tree) tree = new TreeNodeRegister(reg);
        return tree;
    }
    else {
        LOG(1, "    NOT YET IMPLEMENTED -- getParentRegTree with multiple parents");
        return parents.front()->getRegTree(reg);
    }
}

void SearchHelper::handleKnownInstruction(SearchState *state) {
    auto capstone = state->getInstruction()->getSemantic()->getCapstone();
    if(!capstone) return;

    static bool knownInstruction[X86_INS_ENDING] = {};
    knownInstruction[X86_INS_ADD] = true;
    knownInstruction[X86_INS_LEA] = true;
    knownInstruction[X86_INS_MOVSXD] = true;

    enum {
        MODE_UNKNOWN,
        MODE_REG_REG,
        MODE_MEM_REG,
    } mode = MODE_UNKNOWN;

#ifdef ARCH_X86_64
    cs_x86 *x = &capstone->detail->x86;
#elif defined(ARCH_AARCH64)
    cs_arm64 *x = &capstone->detail->arm64;
#endif
    if(knownInstruction[capstone->id]) {
        if(x->op_count == 2
            && x->operands[0].type == X86_OP_REG
            && x->operands[1].type == X86_OP_REG) {

            mode = MODE_REG_REG;
        }
        if(x->op_count == 2
            && x->operands[0].type == X86_OP_MEM
            && x->operands[1].type == X86_OP_REG) {

            mode = MODE_MEM_REG;
        }
    }

    switch(capstone->id) {
    case X86_INS_ADD:
        if(mode == MODE_REG_REG) {
            auto source = x->operands[0].reg;
            auto target = x->operands[1].reg;

            state->setRegTree(target, new TreeNodeAddition(
                getParentRegTree(state, source),
                getParentRegTree(state, target)));
        }
        LOG(1, "        add found");
        break;
    case X86_INS_LEA:
        if(mode == MODE_MEM_REG) {
            auto mem = &x->operands[0].mem;
            auto out = x->operands[1].reg;

            auto tree = makeMemTree(state, mem);
            state->setRegTree(out, tree);
        }
        LOG(1, "        lea found");
        break;
    case X86_INS_MOVSXD:
        if(x->operands[0].type == X86_OP_MEM
            && x->operands[1].type == X86_OP_REG) {

            auto mem = &x->operands[0].mem;
            auto out = x->operands[1].reg;

            auto tree = makeMemTree(state, mem);
            state->setRegTree(out, tree);
        }

        LOG(1, "        movslq found");
        break;
    default:
        LOG(1, "        got instr id " << capstone->id);
        break;
    }
}

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
            SearchHelper helper(&cfg);
            helper.init(i);
            helper.run();
            helper.secondPass();
        }
    }
}
