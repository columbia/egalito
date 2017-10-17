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

void SplitBasicBlock::considerSplittingFor(Function *function,
    NormalLink *link) {

    if(!link) return;

    auto target = dynamic_cast<Instruction *>(&*link->getTarget());
    if(!target) return;

    // if this link points at a different function, discard
    if(target->getParent()->getParent() != function) {
#if 0
        LOG(1, target->getParent()->getParent()->getName()
            << " vs " << function->getName());
#endif
        return;
    }

    // if this link points at the start of an existing block, discard
    auto b = dynamic_cast<Block *>(target->getParent());
    if(b->getChildren()->getIterable()->get(0) == target) {
        return;
    }

    // split at this instruction
    splitPoints.insert(target);
}

void SplitBasicBlock::visit(Function *function) {
    //TemporaryLogLevel tll("pass", 20);

    splitPoints.clear();

    // Look for internal jumps within a function, and split target blocks.
    {std::string foo=StreamAsString()<<"SplitBasicBlock part 1 for " << function->getName();EgalitoTiming timing(foo.c_str(), 100);
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            if(auto linked = dynamic_cast<LinkedInstruction *>(
                instr->getSemantic())) {

                considerSplittingFor(function, dynamic_cast<NormalLink *>(
                    linked->getLink()));
            }
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                instr->getSemantic())) {

                considerSplittingFor(function, dynamic_cast<NormalLink *>(
                    cfi->getLink()));
            }
        }
    }}

    // Follow jump table entries, and split target blocks.
    {EgalitoTiming timing("SplitBasicBlock part 2", 100);
    auto module = dynamic_cast<Module *>(function->getParent()->getParent());
    if(module) {
        auto jumptablelist = module->getJumpTableList();
        for(auto jt : CIter::children(jumptablelist)) {
            if(jt->getFunction() == function) {
                for(auto entry : CIter::children(jt)) {
                    considerSplittingFor(function, dynamic_cast<NormalLink *>(
                        entry->getLink()));
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

    /*LOG(1, "Splitting [" << function->getName() << "] at "
        << splitPoints.size() << " new points");*/

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

