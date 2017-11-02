#include <set>
#include <map>
#include "cancelpush.h"
#include "analysis/call.h"
#include "analysis/walker.h"
#include "analysis/frametype.h"
#include "instr/concrete.h"
#include "instr/semantic.h"
#include "log/log.h"
#include "log/temp.h"

void RegisterSet::dump() const {
    for(size_t i = 0; i < 32; i++) {
        if(s[i]) LOG0(1, " " << i);
    }
    LOG(1, "");
}

RegisterSet& UnusedRegister::get(Function *function) {
    auto it = regsetMap.find(function);
    if(it == regsetMap.end()) {
        return detect(function);
    }
    return it->second;
}

RegisterSet& UnusedRegister::detect(Function *function) {
    DataFlow df;
    auto working = df.getWorkingSet(function);
    auto& regset = regsetMap[function];
    FrameType ft(function);

    //auto module = dynamic_cast<Module *>(function->getParent()->getParent());

    regset.setAll();
    for(const auto& state : working->getStateList()) {
        if(ft.createsFrame() && StateGroup::isPushOrPop(&state)) continue;
        if(StateGroup::isCall(&state)) continue;
        // we must assume ABI use for unknown targets
        //if(StateGroup::isExternalJump(&state, module)) continue;
        if(StateGroup::isReturn(&state)) continue;
        for(const auto& def : state.getRegDefList()) {
            regset.reset(def.first);
        }
        for(const auto& ref : state.getRegRefList()) {
            regset.reset(ref.first);
        }
    }
    return regset;
}

CancelPushPass::CancelPushPass(Program *program)
    : program(program), graph(program), indirectCallees(program) {

    // indirectCallees is unnecessary big because it considers libegalito
    // (and its dependants), but we should try to resolve the target of
    // each indirect call instead of narrowing this
    indirectUnused.setAll();
    for(auto f : indirectCallees.getList()) {
        indirectUnused.intersect(unused.get(f));
        if(indirectUnused.none()) break;
    }
}

void CancelPushPass::visit(Module *module) {
    //TemporaryLogLevel tll("analysis", 10);
    TemporaryLogLevel tll2("pass", 10);

    // more than one root functions exist for a multi-threaded program
    LOG(10, "CancelPushPass: " << module->getName());
    std::vector<Function *> rootList;
    if(module == program->getMain()) {
        for(auto func : CIter::functions(module)) {
            auto node = graph.getNode(func);
            if(indirectCallees.contains(func)) continue;
            if(node->root()) {
                rootList.push_back(func);
                continue;
            }
        }

        LOG(10, std::dec << rootList.size() << " root functions");
        for(auto f : rootList) {
            LOG(10, "     " << f->getName());
        }

        optimize(rootList);
    }
}

bool CancelPushPass::hasIndirectCall(Function *function) {
    for(auto block : CIter::children(function)) {
        for(auto instr : CIter::children(block)) {
            auto semantic = instr->getSemantic();
            if(dynamic_cast<IndirectCallInstruction *>(semantic)) {
                return true;
            }
        }
    }
    return false;
}

void CancelPushPass::determineUseFrom(Function *root) {
    SccOrder sccOrder(&graph);

    LOG(10, "determineUseFrom " << root->getName());

    RegisterSet allUnused;
    allUnused.setAll();
    bool indirectConsidered = false;
    sccOrder.gen(graph.getIDFor(root));
    for(auto vv : sccOrder.get()) {
        for(auto v : vv) {
            auto f = graph.getFunction(v);
            if(!indirectConsidered && hasIndirectCall(f)) {
                LOG(10, f->getName() << " makes an indirect call");
                indirectConsidered = true;
                allUnused.intersect(indirectUnused);
            }
            allUnused.intersect(unused.get(f));
            LOG0(10, f->getName() << " : ");
            IF_LOG(10) allUnused.dump();
            if(allUnused.none()) goto cutoff;
        }
    }

cutoff:
    for(auto vv : sccOrder.get()) {
        for(auto v : vv) {
            auto f = graph.getFunction(v);
            unused.get(f).intersect(allUnused);
        }
    }
}

void CancelPushPass::optimize(const std::vector<Function *>& rootList) {
    SccOrder sccOrder(&graph);

    for(auto func : indirectCallees.getList()) {
        determineUseFrom(func);
    }
    for(auto func : rootList) {
        determineUseFrom(func);
    }
    for(auto func : rootList) {
        if(!unused.get(func).none()) {
            LOG(10, "SPARE REGISTER AVAILABLE: " << func->getName());
            IF_LOG(10) unused.get(func).dump();
            sccOrder.gen(graph.getIDFor(func));
            for(auto vv : sccOrder.get()) {
                for(auto v : vv) {
                    auto f = graph.getFunction(v);
                    if(FrameType(f).createsFrame()) {
                        LOG(10, "maybe optimize " << f->getName());
                    }
                }
            }
        }
    }
}

