#include <assert.h>

#include "findsyscalls.h"
#include "analysis/dataflow.h"
#include "analysis/slicingtree.h"
#include "analysis/usedef.h"
#include "analysis/usedefutil.h"
#include "analysis/walker.h"
#include "chunk/dump.h"
#include "conductor/conductor.h"
#include "log/log.h"

void FindSyscalls::visit(Function *function) {
#ifdef ARCH_X86_64
    LOG(10, "Finding syscalls in function " << function->getName());
    // skip the syscall() function inside libc, as it will definitely not have
    // a constant syscall set, and in fact we actually track calls to it as
    // equivalent to a syscall() instruction.
    if (isSyscallFunction(function)) return;

    auto graph = new ControlFlowGraph(function);
    auto config = new UDConfiguration(graph);
    auto working = new UDRegMemWorkingSet(function, graph);
    auto usedef = new UseDef(config, working);

    SccOrder order(graph);
    order.genFull(0);
    usedef->analyze(order.get());

    for (auto block : CIter::children(function)) {
        for (auto instr : CIter::children(block)) {
            auto assembly = instr->getSemantic()->getAssembly();
            auto state = working->getState(instr);
            if (assembly && assembly->getId() == X86_INS_SYSCALL) {
                std::set<unsigned long> values;
                seen.clear();
                auto rax = X86Register::convertToPhysical(X86_REG_RAX);
                if(getRegisterValue(state, rax, values)) {
                    numberMap[instr] = values;
                }
                else {
                    LOG(1, "WARNING: Unable to determine syscall number for " 
                        << instr->getName() << " inside [" << function->getName() << "]");
                }
            }
            else if (auto cfi = dynamic_cast<ControlFlowInstruction *>(
                         instr->getSemantic())) {
                Function *func_target;
                auto target = cfi->getLink()->getTarget();
                if (auto plt = dynamic_cast<PLTTrampoline *>(target)) {
                    func_target = dynamic_cast<Function *>(plt->getTarget());
                    // some PLT entry hasn't been resolved at this point.
                    // however, since we (presumably) are operating only
                    // on the subset of the callgraph that we care about,
                    // the user will already have been notified about this,
                    // or perhaps it's already on a whitelist somewhere.
                    continue;
                }
                else {
                    func_target = dynamic_cast<Function *>(target);
                }
                if (func_target && isSyscallFunction(function)) {
                    LOG(10, "found call to syscall() function");
                    std::set<unsigned long> values;
                    seen.clear();
                    auto rdi = X86Register::convertToPhysical(X86_REG_RDI);
                    if(getRegisterValue(state, rdi, values)) {
                        numberMap[instr] = values;
                    }
                    else {
                        LOG(1, "WARNING: Unable to determine syscall number for " 
                            << instr->getName() << " inside [" << function->getName() << "]");
                    }
                }
            }
            else {
                continue;
            }
#if 0
            if (!cr.allConstant()) {
                if (function->getName() == "_int_free")
                    cr.cs.insert(0);
                else if (function->getName() == "__spawni_child")
                    cr.cs.insert(1);
                else {
                    LOG(1, "Couldn't resolve all possible syscall values in "
                           "function "
                            << function->getName());
                }
            }
#endif
        }
    }
#else
    assert(0);
#endif
}

bool FindSyscalls::isSyscallFunction(Function *function) {
    if (function->getName() == "syscall") {
        auto module = static_cast<Module *>(function->getParent()->getParent());
        if (module->getLibrary()->getRole() == Library::ROLE_LIBC) return true;
    }
    return false;
}

bool FindSyscalls::getRegisterValue(UDState *state, int curreg, std::set<unsigned long> &valueSet) {
    bool all_constants = true;
    if (seen.find(state) == seen.end()) {
        auto refstates = state->getRegRef(curreg);
        if (refstates.size() == 0) {
            LOG(1, "Failed to find any register definitions for requested register!");
            return false;
        }
        for (auto s : refstates) {
            TreeNode *node = nullptr;
            int count = 0;
            for (auto pair : s->getRegDefList()) {
                if (pair.second) {
                    count++;
                    node = pair.second;
                }
            }
            if (count > 1) {
                TreePrinter tp;
                LOG(1, "More than one definition in a single state!");
                for (auto pair : s->getRegDefList()) {
                    if (pair.second) {
                        pair.second->print(tp);
                    }
                }
            }
            if (auto cnode = dynamic_cast<TreeNodeConstant *>(node)) {
                valueSet.insert(cnode->getValue());
            }
            else if (auto rnode
                = dynamic_cast<TreeNodePhysicalRegister *>(node)) {
                auto reg = rnode->getRegister();
                getRegisterValue(s, reg, valueSet);
            }
            else {
                if (!node) {
                    LOG(1, "No value definition available while tracking value "
                           "of register "
                            << curreg);
                }
                else {
                    LOG(1, "Don't know how to parse node for value of register "
                            << curreg);
                    // s->dumpState();
                }
                all_constants = false;
            }
        }
        seen.insert(state);
    }
    return all_constants;
}
