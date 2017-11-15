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
#include "log/temp.h"

const std::vector<std::string> NonReturnFunction::standardNameList = {
    "exit", "error"
};

void NonReturnFunction::visit(Module *module) {
    size_t size = 0;

    //TemporaryLogLevel tll("pass", 10);
    //TemporaryLogLevel tll2("analysis", 10);

    do {
        size = nonReturnList.size();
        recurse(module);
    } while (size != nonReturnList.size());

    for(auto f : nonReturnList) {
        LOG(1, "marking " << f->getName() << " as non-returning");
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
                    LOG(10, "--Function " << function->getName());
                    IF_LOG(10) cfg.dump();
                    Dominance dom(&cfg);
                    auto pdom = dom.getPostDominators(0);
                    auto nid = cfg.getIDFor(block);
                    if(std::find(pdom.begin(), pdom.end(), nid) == pdom.end()) {
                        continue;
                    }

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
