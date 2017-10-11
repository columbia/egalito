#include "nonreturn.h"
#include "analysis/controlflow.h"
#include "analysis/walker.h"
#include "analysis/dominance.h"
#include "chunk/concrete.h"
#ifdef ARCH_X86_64
    #include "instr/linked-x86_64.h"
#endif
#ifdef ARCH_AARCH64
    #include "instr/linked-aarch64.h"
#endif
#include "log/log.h"

const std::vector<std::string> NonReturnFunction::standardNameList = {
    "exit"
};

void NonReturnFunction::visit(Module *module) {
    size_t size = 0;

    do {
        size = nonReturnList.size();
        recurse(module);
    } while (size != nonReturnList.size());

    for(auto f : nonReturnList) {
        f->setNonreturn();
    }
}

void NonReturnFunction::visit(Function *function) {
    if(inList(function)) return;

    size_t n = 0;
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                instr->getSemantic())) {

                if(hasLinkToNonReturn(cfi)) {
                    ControlFlowGraph cfg(function);
                    //LOG(1, "--Function " << function->getName());
                    //cfg.dump();
                    Dominance dom(&cfg);
                    auto pdom = dom.getPostDominators(0);
                    auto nid = cfg.get(block)->getID();
                    if(std::find(pdom.begin(), pdom.end(), nid) == pdom.end()) {
                        continue;
                    }

                    // check if this instruction is always executed
                    LOG(1, "adding " << function->getName() <<
                        " to the list of non-returning functions");
                    nonReturnList.push_back(function);
                    return;
                }
            }
        }
        n++;
    }
}

bool NonReturnFunction::hasLinkToNonReturn(ControlFlowInstruction *cfi) {
    if(auto pltLink = dynamic_cast<PLTLink *>(cfi->getLink())) {
        auto trampoline = pltLink->getPLTTrampoline();
        auto pltName = trampoline->getTargetSymbol()->getName();
        for(auto name : standardNameList) {
            if(pltName == name) {
                return true;
            }
        }
    }
    else if(auto target = dynamic_cast<Function *>(
        &*cfi->getLink()->getTarget())) {

        if(inList(target)) {
            return true;
        }
    }

    return false;
}

bool NonReturnFunction::inList(Function *function) {
    if(std::find(nonReturnList.begin(), nonReturnList.end(), function)
        != nonReturnList.end()) {

        return true;
    }
    return false;
}
