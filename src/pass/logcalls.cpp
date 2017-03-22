#include <cstdio>
#include "logcalls.h"
#include "conductor/conductor.h"
#include "chunk/find2.h"
#include "chunk/mutator.h"
#include "disasm/disassemble.h"
#include "cminus/print.h"
#include "log/log.h"

static int indent = 0;
Conductor *global_conductor;

static void egalito_log_function_name(unsigned long address, const char *dir) {
    for(int i = 0; i < indent; i ++) egalito_printf("    ");

    /*auto func = ChunkFind2(global_conductor).findFunctionContaining(address);
    if(func) {
        egalito_printf("%s %lx [%s+%lu]\n", dir, address,
            func->getName().c_str(), address - func->getAddress());
    }
    else*/ {
        egalito_printf("%s %lx\n", dir, address);
    }
}

extern "C" void egalito_log_function(void) {
    unsigned long address = (unsigned long)__builtin_return_address(0) - 5;
    egalito_log_function_name(address, "->");
    indent ++;
}

extern "C" void egalito_log_function_ret(void) {
    unsigned long address = (unsigned long)__builtin_return_address(0) - 5;
    indent --;
    egalito_log_function_name(address, "<-");
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
    if(function->getName() == "_start") return;
    if(function->getName() == "log_function") return;
    if(function->getName() == "log_function_ret") return;

    LOG(1, "adding logging to function [" << function->getName() << "]");
    addEntryInstructionsAt(function->getChildren()->getIterable()->get(0));

    recurse(function);
}

void LogCallsPass::visit(Instruction *instruction) {
    auto s = instruction->getSemantic();
    if(dynamic_cast<ReturnInstruction *>(s)) {
        addExitInstructionsAt(instruction);
    }
}

void LogCallsPass::addEntryInstructionsAt(Block *block) {
    auto callIns = new Instruction();
    auto callSem = new ControlFlowInstruction(callIns, "\xe8", "call", 4);
    callSem->setLink(new NormalLink(loggingBegin));
    callIns->setSemantic(callSem);
    ChunkMutator(block).prepend(callIns);
}

void LogCallsPass::addExitInstructionsAt(Instruction *instruction) {
    auto callIns = new Instruction();
    auto callSem = new ControlFlowInstruction(callIns, "\xe8", "call", 4);
    callSem->setLink(new NormalLink(loggingEnd));
    callIns->setSemantic(callSem);
    ChunkMutator(instruction->getParent())
        .insertBefore(instruction, callIns);
}
