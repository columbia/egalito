#include <cstdio>
#include <assert.h>
#include "loginstr.h"
#include "conductor/conductor.h"
#include "instr/concrete.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "cminus/print.h"
#include "pass/switchcontext.h"
#include "snippet/hook.h"
#include "log/log.h"

extern Conductor *egalito_conductor;

extern "C"
void egalito_log_instruction_pretty(unsigned long address) {
    auto func = ChunkFind2(egalito_conductor).findFunctionContaining(address);
    if(func) {
        // the offset is given in the transformed binary...
        egalito_printf("%lx [%s+%lu]\n", address,
            func->getName().c_str(), address - func->getAddress());
    }
    else {
        egalito_printf("%lx\n", address);
    }
}

extern "C"
void egalito_log_instruction(unsigned long address) {
#ifdef ARCH_X86_64
    #define DISTANCE_FROM_ENTRY     11 // 5 for call instruction, 1 for pushfd, 5 for lea 0x80(%esp), %esp
#elif defined(ARCH_AARCH64)
    #define DISTANCE_FROM_ENTRY     12
#elif defined(ARCH_RISCV)
    #define DISTANCE_FROM_ENTRY     -1
    assert(0); // XXX: no idea
#endif
    egalito_log_instruction_pretty(address - DISTANCE_FROM_ENTRY);
}

LogInstructionPass::LogInstructionPass(Conductor *conductor) {
    auto lib = conductor->getProgram()->getEgalito();
    if(!lib) throw "LogInstructionPass requires libegalito.so to be transformed";

    loggingFunc = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_instruction", lib);
    if(!loggingFunc) {
        throw "LogInstructionPass can't find log functions";
    }

    SwitchContextPass switcher;
    loggingFunc->accept(&switcher);

    LOG(1, "setting instruction hook to " << (void *)egalito_log_instruction);
    set_instruction_hook(egalito_log_instruction);

    instrument.setAdvice(loggingFunc);
    instrument.setPredicate([](Function *function) {
#if 1
        return !function->hasName("egalito_log_instruction")
            && !function->hasName("egalito_log_instruction_pretty")
            && !function->hasName("egalito_log_instruction_call")

            && !function->hasName("__GI___libc_write")
            && !function->hasName("__write_nocancel")

            && !function->hasName("__GI__IO_file_doallocate")

            && !function->hasName("$d")
        ;
#else
        return function->getName() == "main";
#endif
    });
}

void LogInstructionPass::visit(Function *function) {
    function->accept(&instrument);
}
