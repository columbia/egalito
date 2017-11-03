#include <sstream>
#include <iomanip>
#include <regex>
#include <set>
#include "controlflow.h"
#include "analysis/jumptable.h"
#include "chunk/concrete.h"
#include "elf/symbol.h"
#include "instr/concrete.h"
#include "pass/chunkpass.h"
#include "log/log.h"

void ControlFlowNode::addLink(const ControlFlowLink &link) {
    links.emplace_back(new ControlFlowLink(link));
}

void ControlFlowNode::addReverseLink(const ControlFlowLink &rlink) {
    reverseLinks.emplace_back(new ControlFlowLink(rlink));
}

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

ControlFlowGraph::~ControlFlowGraph() {
    // link should not be deleted everytime node is deleted because node
    // can be copied
    for(auto& node : graph) {
        for(auto link : node.forwardLinks()) {
            delete &*link;
        }
        for(auto link : node.backwardLinks()) {
            delete &*link;
        }
    }
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
#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(cfi->getMnemonic() == "bl") {
            if(auto plt = dynamic_cast<PLTLink *>(link)) {
                if(!doesPLTReturn(plt->getPLTTrampoline())) fallThrough = false;
            }
            else if(auto func = dynamic_cast<Function *>(&*link->getTarget())) {
                if(!doesReturn(func)) fallThrough = false;
            }
        }
#endif
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
        if(ij->getMnemonic() == "callq") {
            fallThrough = true;
        }
        else {
            fallThrough = false;
        }
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(ij->getMnemonic() == "blr") {
            fallThrough = true;
        }
        else if(auto jt = ij->getJumpTable()) {
            LOG(10, "jumptable at " << i->getAddress() << "targeting to...");
            std::set<address_t> added;
            for(auto entry : CIter::children(jt)) {
                auto link = dynamic_cast<NormalLink *>(entry->getLink());
                if(link && link->getTarget()) {
                    auto it = added.find(link->getTargetAddress());
                    if(it != added.end()) continue;

                    added.insert(link->getTargetAddress());
                    LOG(10, "" << link->getTarget()->getName());
                    if(auto v = dynamic_cast<Instruction *>(
                        &*link->getTarget())) {

                        auto parent = dynamic_cast<Block *>(v->getParent());
                        auto parentID = blockMapping[parent];
                        auto offset = link->getTargetAddress()
                            - parent->getAddress();
                        graph[id].addLink(ControlFlowLink(parentID, offset));
                        graph[parentID].addReverseLink(
                            ControlFlowLink(id, i->getAddress()
                                - i->getParent()->getAddress()));
                    }
                }
            }
        }
#endif
    }
    else if(dynamic_cast<ReturnInstruction *>(i->getSemantic())) {
        // return instruction, no intra-function links
    }
    else if(dynamic_cast<BreakInstruction *>(i->getSemantic())) {
        // break instruction, no intra-funtion links
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

bool ControlFlowGraph::doesReturn(Function *function) {
    static const std::vector<std::string> noreturns = {
        "__GI___libc_fatal", "__GI___assert_fail", "__stack_chk_fail",
        "__malloc_assert", "_exit", "_dl_signal_error", "abort", "lose"
    };

    if(!function->returns()) return false;

    for(auto fn : noreturns) {
        if(function->getName() == fn) return false;
    }
    if(auto symbol = function->getSymbol()) {
        for(auto s : symbol->getAliases()) {
            for(auto fn : noreturns) {
                if(std::string(s->getName()) == fn) return false;
            }
        }
    }

    return true;
}

bool ControlFlowGraph::doesPLTReturn(PLTTrampoline *pltTrampoline) {
    static const std::vector<std::string> PLTnoreturns = {
        "__cxa_throw@plt", "exit@plt", "__stack_chk_fail@plt",
        "_ZSt20__throw_out_of_rangePKc@plt",
        "_ZSt19__throw_logic_errorPKc@plt",
        "_ZSt17__throw_bad_allocv@plt",
        "__assert_fail@plt"
    };

    for(auto plt : PLTnoreturns) {
        if(pltTrampoline->getName() == plt) return false;
    }

    return true;
}

void ControlFlowGraph::dump() {
    LOG(1, "Control flow graph:");
    for(auto& node : graph) {
        LOG(1, "    " << node.getDescription());
        LOG0(1, "        forward links:");
        for(const auto& link : node.forwardLinks()) {
            auto cflink = dynamic_cast<ControlFlowLink *>(&*link);
            LOG0(1, " " << cflink->getTargetID() << " ("
                << graph[cflink->getTargetID()].getBlock()->getName()
                << ") + " << std::dec << cflink->getOffset() << ";");
        }
        LOG(1, "");
        LOG0(1, "        backward links:");
        for(auto link : node.backwardLinks()) {
            auto cflink = dynamic_cast<ControlFlowLink *>(&*link);
            LOG0(1, " " << cflink->getTargetID() << " ("
                << graph[cflink->getTargetID()].getBlock()->getName()
                << ") + " << std::dec << cflink->getOffset() << ";");
        }
        LOG(1, "");
    }
}

void ControlFlowGraph::dumpDot() {
    std::regex e("bb\\+([0-9]+)");

    LOG(1, "Control flow graph (DOT):");
    LOG(1, "digraph G {");
    for(auto& node : graph) {
        std::smatch match1, match2;

        auto nodeName = node.getBlock()->getName();
        std::regex_search(nodeName, match1, e);

        for(const auto& link : node.forwardLinks()) {
            auto cflink = dynamic_cast<ControlFlowLink *>(&*link);
            auto linkName = graph[cflink->getTargetID()].getBlock()->getName();
            std::regex_search(linkName, match2, e);

            LOG(1, " \"" << node.getID() << "(" << match1[1] << ")\""
                << " -> \"" << cflink->getTargetID()
                << "(" << match2[1] << ")\"");
        }
    }
    LOG(1, "}");
}

