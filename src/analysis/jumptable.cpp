#include <utility>
#include <capstone/capstone.h>
#include "jumptable.h"
#include "controlflow.h"
#include "chunk/instruction.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "log/log.h"

class SearchHelper {
private:
    ControlFlowGraph *cfg;
    std::vector<bool> regs;
    std::vector<bool> visited;
    std::vector<std::pair<ControlFlowNode *, Instruction *>> positions;
public:
    SearchHelper(ControlFlowGraph *cfg)
        : cfg(cfg), regs(X86_REG_ENDING), visited(cfg->getCount()) {}
    void init(Instruction *i);

    void run();
};

void SearchHelper::init(Instruction *i) {
    auto j = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic());
    auto block = dynamic_cast<Block *>(i->getParent());
    auto node = cfg->get(block);
    LOG(1, "search for jump table at " << i->getName());
    regs[j->getRegister()] = true;

    positions.push_back(std::make_pair(node, i));
}

void SearchHelper::run() {
    Disassemble::Handle handle(true);
    while(positions.size() > 0) {
        auto p = positions.front();
        positions.erase(positions.begin());
        auto node = p.first;
        Instruction *instruction = p.second;

        if(visited[node->getID()]) continue;
        visited[node->getID()] = true;

        LOG(1, "visit " << node->getDescription());

        auto insList = node->getBlock()->getChildren()->getIterable();
        for(int index = insList->indexOf(instruction); index >= 0; index --) {
            Instruction *i = insList->get(index);
            ChunkDumper dumper;
            dumper.visit(i);

            if(auto capstone = i->getSemantic()->getCapstone()) {
                //LOG(1, "        (cs " << capstone << ")");
                auto detail = capstone->detail;
                for(size_t r = 0; r < detail->regs_read_count; r ++) {
                    LOG(1, "        read reg "
                        << cs_reg_name(handle.raw(), detail->regs_read[r]));
                }
                for(size_t r = 0; r < detail->regs_write_count; r ++) {
                    LOG(1, "        write reg "
                        << cs_reg_name(handle.raw(), detail->regs_write[r]));
                }
            }
        }

        for(auto link : node->backwardLinks()) {
            auto newNode = cfg->get(link.first);
            if(!visited[newNode->getID()]) {
                auto offset = link.second;
                Instruction *newStart
                    = newNode->getBlock()->getChildren()->getSpatial()->find(
                        newNode->getBlock()->getAddress() + offset);
                LOG(1, "    start at offset " << offset << " -> " << newStart);
                positions.push_back(std::make_pair(newNode, newStart));
            }
        }
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
        }
    }
}
