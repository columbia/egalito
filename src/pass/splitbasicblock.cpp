#include <set>
#include "splitbasicblock.h"
#include "analysis/controlflow.h"
#include "operation/mutator.h"

#include <assert.h>
#include <cstdio>  // for std::fflush
#include "chunk/dump.h"
#include "log/log.h"
#include "log/registry.h"

void SplitBasicBlock::visit(Function *function) {
    std::set<Instruction *> splitPoints;
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            if(auto linked = dynamic_cast<LinkedInstruction *>(
                instr->getSemantic())) {

                if(auto link = dynamic_cast<NormalLink *>(
                    linked->getLink())) {

                    auto target =
                        dynamic_cast<Instruction *>(&*link->getTarget());
                    if(!target) continue;

                    if(target->getParent()->getParent() != function) {
#if 0
                        LOG(1, target->getParent()->getParent()->getName()
                            << " vs " << function->getName());
#endif
                        continue;
                    }

                    auto b = dynamic_cast<Block *>(target->getParent());
                    if(b->getChildren()->getIterable()->get(0) != target) {
                        splitPoints.insert(target);
                    }
                }
            }
        }
    }

    auto module = dynamic_cast<Module *>(function->getParent()->getParent());
    if(module) {
        auto jumptablelist = module->getJumpTableList();
        for(auto jt : CIter::children(jumptablelist)) {
            if(jt->getFunction() == function) {
                for(auto entry : CIter::children(jt)) {
                    auto link = dynamic_cast<NormalLink *>(entry->getLink());
                    if(link) {
                        auto target =
                            dynamic_cast<Instruction *>(&*link->getTarget());
                        if(!target) continue;

                        // usually a jump to _nocancel version
                        if(target->getParent()->getParent() != function) {
#if 0
                            LOG(1, target->getParent()->getParent()->getName()
                                << " vs " << function->getName());
#endif
                            continue;
                        }

                        auto b = dynamic_cast<Block *>(target->getParent());
                        if(b->getChildren()->getIterable()->get(0) != target) {
                            splitPoints.insert(target);
                        }
                    }
                }
            }
        }
    }

#if 0
    size_t org = function->getSize();
    if(splitPoints.size() > 0) {
        ChunkDumper dump;
        function->accept(&dump);
    }
#endif

    ChunkMutator m(function);
    for(auto instr : splitPoints) {
        //LOG(1, "    split at 0x" << std::hex << instr->getAddress());
        m.splitBlockBefore(instr);
    }

#if 0
    if(splitPoints.size() > 0) {
        m.updatePositions();

        GroupRegistry::getInstance()->applySetting("analysis", 20);

        //ChunkDumper dump;
        //function->accept(&dump);

        ControlFlowGraph cfg(function);
        //cfg.dump();
        std::cout.flush();
        std::fflush(stdout);
        cfg.check();

        assert(org == function->getSize());

        GroupRegistry::getInstance()->applySetting("analysis", 9);
    }
#endif
}

