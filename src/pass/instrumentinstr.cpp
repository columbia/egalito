#include <iomanip>
#include "pass/instrumentinstr.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "instr/semantic.h"
#include "instr/linked-x86_64.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"

void InstrumentInstructionPass::visit(Function *function) { 
    if(!shouldApply(function)) return;

    for(size_t i = 0; i < function->getChildren()->getIterable()->getCount(); i ++) {
        auto block = function->getChildren()->getIterable()->get(i);
        visit(block);
    }
}

void InstrumentInstructionPass::visit(Block *block) { 
    for(size_t i = 0; i < block->getChildren()->getIterable()->getCount(); i += 6) {
        auto instr = block->getChildren()->getIterable()->get(i);
        visit(instr);
    }
}

void InstrumentInstructionPass::visit(Instruction *instruction) {
    addAdvice(instruction, func, false);
}

void InstrumentInstructionPass::addAdvice(
    Instruction *point, Function *advice, bool after) {

#ifdef ARCH_X86_64
    // pushfd
    auto saveFlagsIns = Disassemble::instruction({0x9c});

    // lea -0x80(%rsp), rsp
    auto subIns = Disassemble::instruction({0x48, 0x8d, 0x64, 0x24, 0x80});

    auto callIns = new Instruction();
    auto callSem
        = new ControlFlowInstruction(X86_INS_CALL, callIns, "\xe8", "callq", 4);
    callSem->setLink(new NormalLink(advice, Link::SCOPE_EXTERNAL_JUMP));
    callIns->setSemantic(callSem);

    // lea 0x80(%rsp), rsp
    auto addIns = Disassemble::instruction({0x48, 0x8d, 0xa4, 0x24, 0x80, 0x00, 0x00, 0x00});

    // popfd
    auto restoreFlagsIns = Disassemble::instruction({0x9d});

    auto block = point->getParent();

    if(after) {
        ChunkMutator(block).insertAfter(point, addIns);
        ChunkMutator(block).insertAfter(point, restoreFlagsIns);
        ChunkMutator(block).insertAfter(point, callIns);
        ChunkMutator(block).insertAfter(point, saveFlagsIns);
        ChunkMutator(block).insertAfter(point, subIns);
    }
    else {  // don't reverse instructions case
        ChunkMutator(block).insertBefore(point, subIns);
        ChunkMutator(block).insertBefore(point, saveFlagsIns);
        ChunkMutator(block).insertBefore(point, callIns);
        ChunkMutator(block).insertBefore(point, restoreFlagsIns);
        ChunkMutator(block).insertBefore(point, addIns);
    }
#endif
}
