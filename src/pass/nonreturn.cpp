#include "nonreturn.h"
#include "analysis/controlflow.h"
#include "analysis/dominance.h"
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "analysis/walker.h"
#include "chunk/concrete.h"
#ifdef ARCH_X86_64
    #include "instr/linked-x86_64.h"
#endif
#ifdef ARCH_AARCH64
    #include "instr/linked-aarch64.h"
#endif
#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

// known to be non-returning in glibc (not all are standard)
const std::vector<std::string> NonReturnFunction::knownList = {
    "exit", "_exit", "abort",
    "__libc_fatal", "__assert_fail", "__stack_chk_fail",
    "__malloc_assert", "_dl_signal_error",
    "__cxa_throw",
    "_ZSt20__throw_out_of_rangePKc",
    "_ZSt19__throw_logic_errorPKc",
    "_ZSt17__throw_bad_allocv",
};

void NonReturnFunction::visit(FunctionList *functionList) {
    size_t size = 0;

    //TemporaryLogLevel tll("pass", 10);
    //TemporaryLogLevel tll2("analysis", 10);

    do {
        size = nonReturnList.size();
        recurse(functionList);
    } while(size != nonReturnList.size());
}

// Since Dominance requires an exit node to be spotted in the control flow
// graph, we should do this in two passes
void NonReturnFunction::visit(Function *function) {
    if(!function->returns()) return;

    //TemporaryLogLevel tll("pass", 10, function->hasName("mabort"));

    // step-1
    std::vector<Instruction *> GNUErrorCalls;
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                instr->getSemantic())) {

                if(!cfi->returns()) continue;

                if(hasLinkToNeverReturn(cfi)) {
                    LOG(10, "non-returning call at "
                        << std::hex << instr->getAddress());
                    cfi->setNonreturn();
                    continue;
                }

                if(hasLinkToGNUError(cfi)) {
                    GNUErrorCalls.push_back(instr);
                }
            }
        }
    }

    if(!GNUErrorCalls.empty()) {
        ControlFlowGraph cfg(function);
        UDConfiguration config(&cfg);
        UDRegMemWorkingSet working(function, &cfg);
        UseDef usedef(&config, &working);

        SccOrder order(&cfg);
        order.genFull(0);
        usedef.analyze(order.get());

        for(auto instr : GNUErrorCalls) {
            bool found;
            int value;
            std::tie(found, value) = getArg0Value(working.getState(instr));
            if(found && value != 0) {
                auto cfi = dynamic_cast<ControlFlowInstruction *>(
                    instr->getSemantic());
                cfi->setNonreturn();
            }
        }
    }

    // step-2
    if(neverReturns(function)) {
        LOG(10, "=== " << function->getName() << " never returns");
        function->setNonreturn();
        nonReturnList.push_back(function);
    }
}

bool NonReturnFunction::neverReturns(Function *function) {
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            if(auto cfi = dynamic_cast<ControlFlowInstruction *>(
                instr->getSemantic())) {

                if(!cfi->returns()) {
                    ControlFlowGraph cfg(function);
                    LOG(10, "--Function " << function->getName());
                    IF_LOG(10) {
                        ChunkDumper dump;
                        function->accept(&dump);
                        cfg.dump();
                        cfg.dumpDot();
                        std::cout.flush();
                    }
                    Dominance dom(&cfg);
                    auto pdom = dom.getPostDominators(0);
                    auto nid = cfg.getIDFor(block);
                    if(std::find(pdom.begin(), pdom.end(), nid) == pdom.end()) {
                        continue;
                    }

                    return true;
                }
            }
        }
    }
    return false;
}

bool NonReturnFunction::hasLinkToNeverReturn(ControlFlowInstruction *cfi) {
    if(auto pltLink = dynamic_cast<PLTLink *>(cfi->getLink())) {
        auto trampoline = pltLink->getPLTTrampoline();
        auto pltName = trampoline->getTargetSymbol()->getName();
        for(auto name : knownList) {
            if(pltName == name) {
                return true;
            }
        }
    }
    else if(auto target = dynamic_cast<Function *>(
        &*cfi->getLink()->getTarget())) {

        if(!target->returns()) return true;
        if(inList(target)) return true;
        for(auto name : knownList) {
            if(target->hasName(name)) return true;
        }
    }

    return false;
}

bool NonReturnFunction::hasLinkToGNUError(ControlFlowInstruction *cfi) {
    if(auto pltLink = dynamic_cast<PLTLink *>(cfi->getLink())) {
        auto trampoline = pltLink->getPLTTrampoline();
        auto pltName = trampoline->getTargetSymbol()->getName();
        return pltName == std::string("error");
    }
    else if(auto target = dynamic_cast<Function *>(
        &*cfi->getLink()->getTarget())) {

        return target->hasName("error");
    }
    return false;
}

std::tuple<bool, int> NonReturnFunction::getArg0Value(UDState *state) {
    using ConstantForm =
        TreePatternCapture<TreePatternTerminal<TreeNodeConstant>>;
    bool found = false;
    int value = 0;
    auto pred = [&](UDState *state, TreeCapture cap) {
        if(auto tree = dynamic_cast<TreeNodeConstant *>(cap.get(0))) {
            found = true;
            value = tree->getValue();
            return true;
        }
        return false;
    };

#ifdef ARCH_X86_64
    FlowUtil::searchUpDef<ConstantForm>(state, X86Register::R5, pred);
#elif defined(ARCH_AARCH64)
    FlowUtil::searchUpDef<ConstantForm>(state, AARCH64GPRegister::R0, pred);
#endif

    return std::make_tuple(found, value);

}

bool NonReturnFunction::inList(Function *function) {
    if(std::find(nonReturnList.begin(), nonReturnList.end(), function)
        != nonReturnList.end()) {

        return true;
    }
    return false;
}
