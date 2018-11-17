#include <cstdio>
#include <assert.h>
#include "logcalls.h"
#include "conductor/conductor.h"
#include "instr/concrete.h"
#include "operation/find2.h"
#include "operation/mutator.h"
#include "disasm/disassemble.h"
#include "cminus/print.h"
#include "pass/switchcontext.h"
#include "snippet/hook.h"
#include "log/log.h"

static int indent = 0;
extern Conductor *egalito_conductor;
extern bool egalito_init_done;

extern "C"
void egalito_log_function_name(unsigned long address, int dir) {
    indent += dir;
    //for(int i = 0; i < indent; i ++) egalito_printf("    ");
    egalito_printf("%d ", indent);

    auto arrow = dir > 0 ? "->" : "<-";
    // we cannot do this yet (on some platform). func->getName().c_str()
    // below will create a memory object in loader which will be destoryed
    // at the end of this function.
    auto func = ChunkFind2(egalito_conductor).findFunctionContaining(address);
    if(egalito_init_done && func) {
        // the offset is given in the transformed binary...
        egalito_printf("%s %lx [%s+%lu]\n", arrow, address,
            func->getName().c_str(), address - func->getAddress());
    }
    else {
        egalito_printf("%s %lx\n", arrow, address);
    }
}

extern "C"
void egalito_log_function(unsigned long address) {
#ifdef ARCH_X86_64
    #define DISTANCE_FROM_ENTRY     9
#elif defined(ARCH_AARCH64)
    #define DISTANCE_FROM_ENTRY     12
#elif defined(ARCH_RISCV)
    #define DISTANCE_FROM_ENTRY     -1
    assert(0); // XXX: no idea
#endif
    egalito_log_function_name(address - DISTANCE_FROM_ENTRY, 1);
}

extern "C"
void egalito_log_function_ret(unsigned long address) {
#ifdef ARCH_X86_64
    #define DISTANCE_FROM_EXIT      4
#elif defined(ARCH_AARCH64)
    #define DISTANCE_FROM_EXIT      4
#elif defined(ARCH_RISCV)
    #define DISTANCE_FROM_EXIT      -1
    assert(0); // XXX: no idea
#endif
    egalito_log_function_name(address + DISTANCE_FROM_EXIT, -1);
}

LogCallsPass::LogCallsPass(Conductor *conductor) {
    auto lib = conductor->getProgram()->getEgalito();
    if(!lib) throw "LogCallsPass requires libegalito.so to be transformed";

    loggingBegin = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_function_entry", lib);
    loggingEnd = ChunkFind2(conductor).findFunctionInModule(
        "egalito_hook_function_exit", lib);
    if(!loggingBegin || !loggingEnd) {
        throw "LogCallsPass can't find log functions";
    }

    SwitchContextPass switcher;
    loggingBegin->accept(&switcher);
    loggingEnd->accept(&switcher);

    set_function_entry_hook(egalito_log_function);
    set_function_exit_hook(egalito_log_function_ret);

    instrument.setEntryAdvice(loggingBegin);
    instrument.setExitAdvice(loggingEnd);
    instrument.setPredicate([](Function *function) {
        return !function->hasName("egalito_log_function")
            && !function->hasName("egalito_log_function_ret")
            && !function->hasName("egalito_log_function_name")

            && !function->hasName("__GI___libc_write")
            && !function->hasName("__write_nocancel")

            && !function->hasName("__GI__IO_file_doallocate")

            && !function->hasName("$d")
        ;
    });
}

void LogCallsPass::visit(Function *function) {
    function->accept(&instrument);
}
