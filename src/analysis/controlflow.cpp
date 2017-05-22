#include <sstream>
#include <iomanip>
#include "controlflow.h"
#include "chunk/concrete.h"
#include "instr/concrete.h"
#include "pass/chunkpass.h"
#include "log/log.h"

std::string ControlFlowNode::getDescription() {
    std::ostringstream stream;
    stream << "node " << getID()
        << " (" << getBlock()->getName() << ")";
    return stream.str();
}

ControlFlowGraph::ControlFlowGraph(Function *function) {
    // do a breadth-first pass over the function
    construct(function);
}

void ControlFlowGraph::construct(Function *function) {
    ControlFlowNode::id_t count = 0;
    for(auto b : function->getChildren()->getIterable()->iterable()) {
        blockMapping[b] = count;
        graph.push_back(ControlFlowNode(count, b));
        count ++;
    }

    for(auto b : function->getChildren()->getIterable()->iterable()) {
        construct(b);
    }
}

void ControlFlowGraph::construct(Block *block) {
    auto id = blockMapping[block];
    auto i = block->getChildren()->getIterable()->getLast();
    bool fallThrough = false;
    if(auto cfi = dynamic_cast<ControlFlowInstruction *>(i->getSemantic())) {
#ifdef ARCH_X86_64
        if(cfi->getMnemonic() != "jmp") {
            // fall-through to next block
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(cfi->getMnemonic() != "b") {
#endif
            fallThrough = true;
        }

        auto link = i->getSemantic()->getLink();
#ifdef ARCH_X86_64
        if(cfi->getMnemonic() != "callq" && link && link->getTarget()) {
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(cfi->getMnemonic() != "bl" && link && link->getTarget()) {
#endif
            auto target = link->getTarget();
            if(auto v = dynamic_cast<Block *>(&*target)) {
                auto other = blockMapping[v];
                graph[id].addLink(ControlFlowLink(other));
                graph[other].addReverseLink(
                    ControlFlowLink(id,
                        i->getAddress() - i->getParent()->getAddress()));
#ifdef ARCH_AARCH64
                throw "this case breaks splitbasicblock pass";
#endif
            }
            else if(auto v = dynamic_cast<Instruction *>(&*target)) {
                // Currently, Blocks can have jumps incoming to the middle
                // of the Block. So we may have a nonzero offset here.
                auto parent = dynamic_cast<Block *>(v->getParent());
                auto parentID = blockMapping[parent];
                auto offset = link->getTargetAddress() - parent->getAddress();
                graph[id].addLink(ControlFlowLink(parentID, offset));
                graph[parentID].addReverseLink(
                    ControlFlowLink(id,
                        i->getAddress() - i->getParent()->getAddress()));
            }
        }
    }
    else if(auto ij = dynamic_cast<IndirectJumpInstruction *>(i->getSemantic())) {
#ifdef ARCH_X86_64
        LOG(1, "How should we handle IndirectJumpInstruction for X86_64 CFG?");
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(ij->getMnemonic() == "blr") {
            fallThrough = true;
        }
        else {
            // make a forward link to each target of jump table jumps
            auto function = dynamic_cast<Function *>(block->getParent());
            auto module = dynamic_cast<Module *>(
                function->getParent()->getParent());
            if(!module) {
                throw "how do we get module now?";
            }
            auto jumptablelist = module->getJumpTableList();
            for(auto jt : CIter::children(jumptablelist)) {
                if(jt->getInstruction() == i) {
                    for(auto entry : CIter::children(jt)) {
                        auto link =
                            dynamic_cast<NormalLink *>(entry->getLink());
                        if(link && link->getTarget()) {
                            if(auto v = dynamic_cast<Instruction *>(
                                &*link->getTarget())) {

                                auto parent = dynamic_cast<Block *>(v->getParent());
                                auto parentID = blockMapping[parent];
                                auto offset = link->getTargetAddress()
                                    - parent->getAddress();
                                graph[id].addLink(ControlFlowLink(parentID,
                                                                  offset));
                                graph[parentID].addReverseLink(
                                    ControlFlowLink(id,
                                        i->getAddress()
                                        - i->getParent()->getAddress()));
                            }
                        }
                    }
                }
            }
        }
#endif
    }
    else if(dynamic_cast<ReturnInstruction *>(i->getSemantic())) {
        // return instruction, no intra-function links
    }
    else {
        // fall through (including IndirectCallInstruction)
        fallThrough = true;
    }

    if(fallThrough) {
        auto list = dynamic_cast<Function *>(block->getParent())
            ->getChildren()->getIterable();
        auto index = list->indexOf(block);
        if(index + 1 < list->getCount()) {
            auto other = blockMapping[list->get(index + 1)];
            graph[id].addLink(ControlFlowLink(other, 0, false));
            graph[other].addReverseLink(
                ControlFlowLink(id,
                    i->getAddress() - i->getParent()->getAddress(),
                    false));
        }
    }
}

void ControlFlowGraph::dump() {
    LOG(10, "Control flow graph:");
    for(auto node : graph) {
        LOG(10, "    " << node.getDescription());
        LOG0(10, "        forward edges:");
        for(auto link : node.forwardLinks()) {
            LOG0(10, " " << link.getID() << " ("
                << graph[link.getID()].getBlock()->getName()
                << ") + " << std::dec << link.getOffset() << ";");
        }
        LOG(10, "");
        LOG0(10, "        backward edges:");
        for(auto link : node.backwardLinks()) {
            LOG0(10, " " << link.getID() << " ("
                << graph[link.getID()].getBlock()->getName()
                << ") + " << std::dec << link.getOffset() << ";");
        }
        LOG(10, "");
    }
}

#if 0
// only good after Blocks are split to (the finest) basic blocks
#include <assert.h>
void ControlFlowGraph::check() {
    for(auto node : graph) {
        // the offset of backwardLinks == where it's jumping from
        // the offset of forwardLinks == where it's jumping to
        for(auto link : node.forwardLinks()) {
            assert(link.getOffset() == 0);
        }
    }
    LOG(1, "cfg ok");
}
#endif
