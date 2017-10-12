#include <set>
#include "splitbasicblock.h"
#include "analysis/controlflow.h"
#include "operation/mutator.h"
#include "util/streamasstring.h"
#include "util/timing.h"

#include <assert.h>
#include <cstdio>  // for std::fflush
#include "chunk/dump.h"
#include "log/log.h"
#include "log/temp.h"

void SplitBasicBlock::visit(Function *function) {
    //TemporaryLogLevel tll("pass", 20);

    std::set<Instruction *> splitPoints;
    {std::string foo=StreamAsString()<<"SplitBasicBlock part 1 for " << function->getName();EgalitoTiming timing(foo.c_str(), 100);
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
    }}

    {EgalitoTiming timing("SplitBasicBlock part 2", 100);
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
    }}

#if 0
    size_t org = function->getSize();
    if(splitPoints.size() > 0) {
        LOG(1, "function in org: " << function->getName());
        ChunkDumper dump;
        function->accept(&dump);
    }
#endif

    {std::string foo=StreamAsString()<<"SplitBasicBlock part 3 for " << function->getName();EgalitoTiming timing(foo.c_str(), 100);
    ChunkMutator m(function);
    for(auto it = splitPoints.rbegin(); it != splitPoints.rend(); it ++) {
        auto instr = *it;
        //LOG(1, "    split at 0x" << std::hex << instr->getAddress());
        m.splitBlockBefore(instr);
    }
    function->getChildren()->clearSpatial();
    }

#if 0
    if(splitPoints.size() > 0) {
        TemporaryLogLevel tll("pass", 10);
        //m.updatePositions();

        LOG(1, "function: " << function->getName());
        ChunkDumper dump;
        function->accept(&dump);

        ControlFlowGraph cfg(function);
        cfg.dump();
        std::cout.flush();
        std::fflush(stdout);

        LOG(1, "org = " << org << " now = " << function->getSize());
        assert(org == function->getSize());
    }
#endif
}

