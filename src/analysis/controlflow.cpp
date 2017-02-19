#include <sstream>
#include <iomanip>
#include "controlflow.h"
#include "chunk/concrete.h"
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
        if(cfi->getMnemonic() != "jmp") {
            // fall-through to next block
            fallThrough = true;
        }

        auto link = i->getSemantic()->getLink();
        if(cfi->getMnemonic() != "callq" && link && link->getTarget()) {
            auto target = link->getTarget();
            if(auto v = dynamic_cast<Block *>(&*target)) {
                auto other = blockMapping[v];
                graph[id].addLink(other);
                graph[other].addReverseLink(id,
                    i->getAddress() - i->getParent()->getAddress());
            }
            else if(auto v = dynamic_cast<Instruction *>(&*target)) {
                // Currently, Blocks can have jumps incoming to the middle
                // of the Block. So we may have a nonzero offset here.
                auto parent = dynamic_cast<Block *>(v->getParent());
                auto parentID = blockMapping[parent];
                auto offset = link->getTargetAddress() - parent->getAddress();
                graph[id].addLink(parentID, offset);
                graph[parentID].addReverseLink(id,
                    i->getAddress() - i->getParent()->getAddress());
            }
        }
    }
    else if(dynamic_cast<ReturnInstruction *>(i->getSemantic())) {
        // return instruction, no intra-function links
    }
    else {
        // fall through
        fallThrough = true;
    }

    if(fallThrough) {
        auto list = dynamic_cast<Function *>(block->getParent())
            ->getChildren()->getIterable();
        auto index = list->indexOf(block);
        if(index + 1 < list->getCount()) {
            auto other = blockMapping[list->get(index + 1)];
            graph[id].addLink(other);
            graph[other].addReverseLink(id,
                i->getAddress() - i->getParent()->getAddress());
        }
    }
}

void ControlFlowGraph::dump() {
    LOG(1, "Control flow graph:");
    for(auto node : graph) {
        LOG(1, "    " << node.getDescription());
        LOG0(1, "        forward edges:");
        for(auto link : node.forwardLinks()) {
            LOG0(1, " " << link.first << " ("
                << graph[link.first].getBlock()->getName()
                << ") + " << std::dec << link.second << ";");
        }
        LOG(1, "");
        LOG0(1, "        backward edges:");
        for(auto link : node.backwardLinks()) {
            LOG0(1, " " << link.first << " ("
                << graph[link.first].getBlock()->getName()
                << ") + " << std::dec << link.second << ";");
        }
        LOG(1, "");
    }
}
