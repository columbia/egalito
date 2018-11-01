#include <algorithm>
#include "call.h"
#include "analysis/reguse.h"
#include "chunk/concrete.h"
#include "chunk/link.h"
#include "instr/semantic.h"
#ifdef ARCH_X86_64
#include "instr/linked-x86_64.h"
#endif
#ifdef ARCH_AARCH64
#include "instr/linked-aarch64.h"
#endif
#ifdef ARCH_RISCV
#include "instr/linked-riscv.h"
#endif

#include "log/log.h"
#include "log/temp.h"

void CallGraphNode::addDownLink(int targetId) {
    downLinks.emplace_back(new CallGraphLink(targetId));
}

void CallGraphNode::addUpLink(int targetId) {
    upLinks.emplace_back(new CallGraphLink(targetId));
}

CallGraph::CallGraph(Program *program) {
    int count = 0;
    for(auto module : CIter::children(program)) {
        for(auto function : CIter::functions(module)) {
            mapping[function] = count;
            nodeList.push_back(CallGraphNode(count, function));
            count++;
        }
    }

    for(auto module : CIter::children(program)) {
        for(auto function : CIter::functions(module)) {
            makeDirectEdges(function);
        }
    }
}

CallGraph::~CallGraph() {
    // link should not be deleted everytime node is deleted because node
    // can be copied
    for(auto& node : nodeList) {
        for(auto link : node.upwardLinks()) {
            delete &*link;
        }
        for(auto link : node.downwardLinks()) {
            delete &*link;
        }
    }
}

void CallGraph::makeDirectEdges(Function *function) {
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(!dynamic_cast<ControlFlowInstruction *>(semantic)) continue;
            auto link = semantic->getLink();
            if(!link) continue;

            if(auto target = dynamic_cast<Function *>(&*link->getTarget())) {
                makeLinks(function, target);
                continue;
            }
            if(auto pltLink = dynamic_cast<PLTLink *>(link)) {
                if(auto target = pltLink->getPLTTrampoline()->getTarget()) {
                    makeLinks(function, static_cast<Function *>(target));
                }
            }
        }
    }
}

void CallGraph::makeLinks(Function *caller, Function *callee) {
    LOG(10, "    " << caller->getName() << " -> " << callee->getName());
    auto node = getNode(caller);
    auto targetNode = getNode(callee);
    node->addDownLink(targetNode->getID());
    targetNode->addUpLink(node->getID());
}


IndirectCalleeList::IndirectCalleeList(Program *program) {
    for(auto module : CIter::children(program)) {
        makeList(module);
    }
}

IndirectCalleeList::IndirectCalleeList(Module *module) {
    makeList(module);
}

bool IndirectCalleeList::contains(Function *function) {
    auto it = indirectCalleeList.find(function);
    return it != indirectCalleeList.end();
}

void IndirectCalleeList::makeList(Module *module) {
    for(auto region : CIter::regions(module)) {
        for(auto dataSection : CIter::children(region)) {
            LOG(10, "dataSection " << dataSection->getName());
            if(dataSection->getName() != ".got.plt") {
                for(auto var : CIter::children(dataSection)) {
                    auto link = var->getDest();
                    if(auto target
                        = dynamic_cast<Function *>(&*link->getTarget())) {

                        LOG(10, "indirectCallee " << target->getName()
                            << " from var " << std::hex << var->getAddress());
                        indirectCalleeList.insert(target);
                    }
                }
            }
        }
    }

#ifdef ARCH_AARCH64
    for(auto function : CIter::functions(module)) {
        for(auto block : CIter::children(function)) {
            for(auto instr : CIter::children(block)) {
                if(auto lli = dynamic_cast<LinkedLiteralInstruction *>(
                    instr->getSemantic())) {

                    if(auto target = dynamic_cast<Function *>(
                        &*lli->getLink()->getTarget())) {

                        indirectCalleeList.insert(target);
                    }
                }
            }
        }
    }
#endif
}

