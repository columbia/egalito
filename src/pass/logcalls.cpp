#include <cstdio>
#include "logcalls.h"
#include "conductor/conductor.h"
#include "instr/concrete.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "cminus/print.h"
#include "pass/switchcontext.h"
#include "log/log.h"

static int indent = 0;
Conductor *global_conductor;

extern "C"
void egalito_log_function_name(unsigned long address, int dir) {
    indent += dir;
    //for(int i = 0; i < indent; i ++) egalito_printf("    ");
    egalito_printf("%d ", indent);

    auto arrow = dir > 0 ? "->" : "<-";
    auto func = ChunkFind2(global_conductor).findFunctionContaining(address);
    if(func) {
        // the offset is given in the transformed binary...
        egalito_printf("%s %lx [%s+%lu]\n", arrow, address,
            func->getName().c_str(), address - func->getAddress());
    }
    else {
        egalito_printf("%s %lx\n", arrow, address);
    }
}

#ifdef ARCH_X86_64
static bool inside_egalito_log_code = false;

extern "C" void egalito_log_function(void) {
    __asm__ (
        "push   %rax\n"
        "push   %rcx\n"
        "push   %rdx\n"
        "push   %rsi\n"
        "push   %rdi\n"
        "push   %r8\n"
        "push   %r9\n"
        "push   %r10\n"
        "push   %r11\n"
    );

    if(!inside_egalito_log_code) {
        inside_egalito_log_code = true;
        // WARNING: if using the -fstack-protector flag, this will break the below address variable
        // You can check if this flag is enabled with the EGALITO_STACK_PROTECTOR macro
        unsigned long address;
        __asm__ (
            "mov    80(%%rsp), %%rax" : "=a"(address)
        );
        address -= 5;
        //unsigned long address = (unsigned long)__builtin_return_address(0) - 5;
        egalito_log_function_name(address, 1);
        inside_egalito_log_code = false;
    }

    __asm__ (
        "pop    %r11\n"
        "pop    %r10\n"
        "pop    %r9\n"
        "pop    %r8\n"
        "pop    %rdi\n"
        "pop    %rsi\n"
        "pop    %rdx\n"
        "pop    %rcx\n"
        "pop    %rax\n"
    );
}

extern "C" void egalito_log_function_ret(void) {
    __asm__ (
        "push   %rax\n"
        "push   %rcx\n"
        "push   %rdx\n"
        "push   %rsi\n"
        "push   %rdi\n"
        "push   %r8\n"
        "push   %r9\n"
        "push   %r10\n"
        "push   %r11\n"
    );

    if(!inside_egalito_log_code) {
        inside_egalito_log_code = true;
        unsigned long address;
        __asm__ (
            "mov    80(%%rsp), %%rax" : "=a"(address)
        );
        address -= 5;
        //unsigned long address = (unsigned long)__builtin_return_address(0) - 5;
        egalito_log_function_name(address, -1);
        inside_egalito_log_code = false;
    }

    __asm__ (
        "pop    %r11\n"
        "pop    %r10\n"
        "pop    %r9\n"
        "pop    %r8\n"
        "pop    %rdi\n"
        "pop    %rsi\n"
        "pop    %rdx\n"
        "pop    %rcx\n"
        "pop    %rax\n"
    );
}
#endif

LogCallsPass::LogCallsPass(Conductor *conductor) {
    global_conductor = conductor;

    auto lib = conductor->getLibraryList()->get("(egalito)");
    if(!lib) throw "LogCallsPass requires libegalito.so to be transformed";

    loggingBegin = ChunkFind2(conductor).findFunctionInModule(
        "egalito_log_function", lib->getElfSpace()->getModule());
    loggingEnd = ChunkFind2(conductor).findFunctionInModule(
        "egalito_log_function_ret", lib->getElfSpace()->getModule());
    if(!loggingBegin || !loggingEnd) {
        throw "LogCallsPass can't find log functions";
    }

#ifdef ARCH_AARCH64
    SwitchContextPass switcher;
    loggingBegin->accept(&switcher);
    loggingEnd->accept(&switcher);

    instrument.setEntryAdvice(loggingBegin);
    instrument.setExitAdvice(loggingEnd);
    instrument.setPredicate([](Function *function) {
        return !function->hasName("egalito_log_function")
            && !function->hasName("egalito_log_function_ret")
            && !function->hasName("egalito_log_function_name")

            && !function->hasName("__GI___libc_write")
            && !function->hasName("__write_nocancel")

            && !function->hasName("__GI__IO_file_doallocate")
        ;
    });
#endif
}

void LogCallsPass::visit(Function *function) {
#ifdef ARCH_X86_64
    if(function->getName() == "egalito_log_function") return;
    if(function->getName() == "egalito_log_function_ret") return;
    if(function->getName() == "__GI___libc_write") return;

    // bugs:
    if(function->getName() == "__GI__IO_file_doallocate") return;

    LOG(1, "adding logging to function [" << function->getName() << "]");
    addEntryInstructionsAt(function->getChildren()->getIterable()->get(0));

    recurse(function);
#else
    function->accept(&instrument);
#endif
}

#ifdef ARCH_X86_64
void LogCallsPass::visit(Instruction *instruction) {
    auto s = instruction->getSemantic();
    if(dynamic_cast<ReturnInstruction *>(s)) {
        addExitInstructionsAt(instruction);
    }
    else if(auto v = dynamic_cast<ControlFlowInstruction *>(s)) {
        if(v->getMnemonic() != "callq"
            && dynamic_cast<ExternalNormalLink *>(s->getLink())) {

            addExitInstructionsAt(instruction);
        }
    }
}

void LogCallsPass::addEntryInstructionsAt(Block *block) {
    auto callIns = new Instruction();
    auto callSem = new ControlFlowInstruction(X86_INS_CALL, callIns, "\xe8", "call", 4);
    callSem->setLink(new NormalLink(loggingBegin));
    callIns->setSemantic(callSem);
    ChunkMutator(block).prepend(callIns);
}

void LogCallsPass::addExitInstructionsAt(Instruction *instruction) {
    auto callIns = new Instruction();
    auto callSem = new ControlFlowInstruction(X86_INS_CALL, callIns, "\xe8", "call", 4);
    callSem->setLink(new NormalLink(loggingEnd));
    callIns->setSemantic(callSem);
    ChunkMutator(instruction->getParent())
        .insertBefore(instruction, callIns);
}
#endif
