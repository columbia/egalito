#include <utility>
#include <capstone/capstone.h>
#include "jumptable.h"
#include "controlflow.h"
#include "chunk/instruction.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "log/log.h"

class SearchState {
private:
    ControlFlowNode *node;
    Instruction *instruction;
    std::vector<bool> regs;
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
};

class SearchHelper {
private:
    Disassemble::Handle handle;
    ControlFlowGraph *cfg;
    std::vector<bool> visited;
    std::vector<SearchState> stateList;
    std::vector<SearchState> transitionList;
    SearchState state;
public:
    SearchHelper(ControlFlowGraph *cfg)
        : handle(true), cfg(cfg), visited(cfg->getCount()) {}
    void init(Instruction *i);

    void run();
private:
    void visitInstruction(Instruction *i);
    const char *printReg(int reg);
};

void SearchHelper::init(Instruction *i) {
    auto j = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic());
    auto block = dynamic_cast<Block *>(i->getParent());
    auto node = cfg->get(block);
    LOG(1, "search for jump table at " << i->getName());

    SearchState startState(node, i);
    startState.addReg(j->getRegister());
    transitionList.push_back(startState);
}

void SearchHelper::run() {
    while(transitionList.size() > 0) {
        this->state = transitionList.front();
        transitionList.erase(transitionList.begin());
        auto node = state.getNode();
        Instruction *instruction = state.getInstruction();

        if(visited[node->getID()]) continue;
        visited[node->getID()] = true;

        LOG(1, "visit " << node->getDescription());

        // visit all prior instructions in this node in backwards order
        auto insList = node->getBlock()->getChildren()->getIterable();
        for(int index = insList->indexOf(instruction); index >= 0; index --) {
            Instruction *i = insList->get(index);
            ChunkDumper dumper;
            dumper.visit(i);

            visitInstruction(i);
            stateList.push_back(state);
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
                SearchState newState = state;
                newState.setNode(newNode);
                newState.setInstruction(newStart);
                transitionList.push_back(newState);
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
        }
    }

    switch(capstone->id) {
    case X86_INS_ADD:
        LOG(1, "        add found");
        break;
    case X86_INS_LEA:
        if(x->operands[0].type == X86_OP_MEM
            && x->operands[1].type == X86_OP_REG) {

            auto mem = &x->operands[0].mem;
            auto out = &x->operands[1].reg;

            if(mem->base != X86_REG_INVALID
                && mem->index != X86_REG_INVALID) {
                LOG(1, "        lea found from " << mem->disp << "("
                    << printReg(mem->base)
                    << "," << printReg(mem->index)
                    << "," << mem->scale << ")");
            }
            else if(mem->base != X86_REG_INVALID) {
                LOG(1, "        lea found from " << mem->disp << "("
                    << printReg(mem->base) << ")");
            }
        }
        LOG(1, "        lea found");
        break;
    case X86_INS_MOVSXD:
        LOG(1, "        movslq found");
        break;
    default:
        LOG(1, "        got intr id " << capstone->id);
        break;
    }
}

const char *SearchHelper::printReg(int reg) {
    return cs_reg_name(handle.raw(), reg);
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
        }
    }
}
