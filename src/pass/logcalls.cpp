#include <cstdio>
#include "logcalls.h"
#include "conductor/conductor.h"
#include "chunk/find2.h"
#include "chunk/mutator.h"
#include "instr/concrete.h"
#include "disasm/disassemble.h"
#include "cminus/print.h"
#include "log/log.h"

static int indent = 0;
Conductor *global_conductor;

static void egalito_log_function_name(unsigned long address, const char *dir) {
    //for(int i = 0; i < indent; i ++) egalito_printf("    ");
    egalito_printf("%d ", indent);

    auto func = ChunkFind2(global_conductor).findFunctionContaining(address);
    if(func) {
        egalito_printf("%s %lx [%s+%lu]\n", dir, address,
            func->getName().c_str(), address - func->getAddress());
    }
    else {
        egalito_printf("%s %lx\n", dir, address);
    }
}

static bool inside_egalito_log_code = false;

extern "C" void egalito_log_function(void) {
#ifdef ARCH_X86_64
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
        egalito_log_function_name(address, "->");
        indent ++;
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
#endif
}

extern "C" void egalito_log_function_ret(void) {
#ifdef ARCH_X86_64
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
        indent --;
        egalito_log_function_name(address, "<-");
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
#endif
}

LogCallsPass::LogCallsPass(Conductor *conductor) {
    global_conductor = conductor;

    auto lib = conductor->getLibraryList()->get("(egalito)");
    if(!lib) throw "LogCallsPass requires libegalito.so to be transformed";

    loggingBegin = ChunkFind2(conductor).findFunctionInSpace(
        "egalito_log_function", lib->getElfSpace());
    loggingEnd = ChunkFind2(conductor).findFunctionInSpace(
        "egalito_log_function_ret", lib->getElfSpace());
    if(!loggingBegin || !loggingEnd) {
        throw "LogCallsPass can't find log functions";
    }
}

void LogCallsPass::visit(Function *function) {
    if(function->getName() == "egalito_log_function") return;
    if(function->getName() == "egalito_log_function_ret") return;
    if(function->getName() == "__GI___libc_write") return;

    // bugs:
    if(function->getName() == "__GI__IO_file_doallocate") return;

    LOG(1, "adding logging to function [" << function->getName() << "]");
    addEntryInstructionsAt(function->getChildren()->getIterable()->get(0));

    recurse(function);
}

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
#ifdef ARCH_X86_64
    auto callIns = new Instruction();
    auto callSem = new ControlFlowInstruction(X86_INS_CALL, callIns, "\xe8", "call", 4);
    callSem->setLink(new NormalLink(loggingBegin));
    callIns->setSemantic(callSem);
    ChunkMutator(block).prepend(callIns);
#endif
}

void LogCallsPass::addExitInstructionsAt(Instruction *instruction) {
#ifdef ARCH_X86_64
    auto callIns = new Instruction();
    auto callSem = new ControlFlowInstruction(X86_INS_CALL, callIns, "\xe8", "call", 4);
    callSem->setLink(new NormalLink(loggingEnd));
    callIns->setSemantic(callSem);
    ChunkMutator(instruction->getParent())
        .insertBefore(instruction, callIns);
#endif
}
