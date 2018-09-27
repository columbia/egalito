#include "instrumentcalls.h"
#include "analysis/frametype.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "instr/semantic.h"
#include "instr/linked-x86_64.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"

void InstrumentCallsPass::useStack(Function *function, FrameType *frame) {
    //TemporaryLogLevel tll("pass", 10);
    LOG(10, "instrumenting " << function->getName() << " in "
        << function->getParent()->getParent()->getName());

    if(entry) {
        addEntryAdvice(function, frame);
    }

    if(exit) {
        addExitAdvice(function, frame);
    }
}

void InstrumentCallsPass::addEntryAdvice(Function *function, FrameType *frame) {
    auto block = function->getChildren()->getIterable()->get(0);
    auto ins = block->getChildren()->getIterable()->get(0);
    addAdvice(ins, entry, false);
}

void InstrumentCallsPass::addExitAdvice(Function *function, FrameType *frame) {
    for(auto ins : frame->getEpilogueInstrs()) {
        addAdvice(ins, exit, false);
        if(auto block = dynamic_cast<Block *>(ins->getParent())) {
            auto top = block->getChildren()->getIterable()->get(0);
            frame->fixEpilogue(ins, top);
        }
    }
}

void InstrumentCallsPass::addAdvice(
    Instruction *point, Function *advice, bool after) {

#ifdef ARCH_X86_64
    // sub $0x8,%rsp
    auto subIns = Disassemble::instruction({0x48, 0x83, 0xec, 0x08});

    // call f
    auto callIns = new Instruction();
    auto callSem
        = new ControlFlowInstruction(X86_INS_CALL, callIns, "\xe8", "callq", 4);
    callSem->setLink(new NormalLink(advice, Link::SCOPE_EXTERNAL_JUMP));
    callIns->setSemantic(callSem);

    // add $0x8,%rsp
    auto addIns = Disassemble::instruction({0x48, 0x83, 0xc4, 0x08});

    auto block = point->getParent();

    if(after) {
        ChunkMutator(block).insertAfter(point, addIns);
        ChunkMutator(block).insertAfter(point, callIns);
        ChunkMutator(block).insertAfter(point, subIns);
    }
    else {
        ChunkMutator(block).insertBefore(point, subIns);
        ChunkMutator(block).insertBefore(point, callIns);
        ChunkMutator(block).insertBefore(point, addIns);
    }
#elif defined(ARCH_AARCH64)
    /* For an arbitrary cutpoint, the base register must be figured out
     * from the frame type. */
    const PhysicalRegister<AARCH64GPRegister> rSP(
        AARCH64GPRegister::SP, true);
    const PhysicalRegister<AARCH64GPRegister> rLR(
        AARCH64GPRegister::LR, true);
    const PhysicalRegister<AARCH64GPRegister> rFP(
        AARCH64GPRegister::FP, true);

    auto bin_stp = AARCH64InstructionBinary(
        0xA9800000 | (-16/8 & 0x7F) << 15
        | rLR.encoding() << 10 | rSP.encoding() << 5 | rFP.encoding());
    auto bin_mov = AARCH64InstructionBinary(0x91000000
        | rSP.encoding() << 5 | rFP.encoding());
    auto bin_bl = AARCH64InstructionBinary(0x94000000);
    auto bin_ldp = AARCH64InstructionBinary(
        0xA8C00000 | (16/8 & 0x7F) << 15
        | rLR.encoding() << 10 | rSP.encoding() << 5 | rFP.encoding());
    auto ins_stp = Disassemble::instruction(bin_stp.getVector());
    auto ins_mov = Disassemble::instruction(bin_mov.getVector());
    auto ins_bl = Disassemble::instruction(bin_bl.getVector());
    ins_bl->getSemantic()->setLink(
        new NormalLink(advice, Link::SCOPE_EXTERNAL_JUMP));
    auto ins_ldp = Disassemble::instruction(bin_ldp.getVector());

    auto block = point->getParent();

    if(after) {
        ChunkMutator(block).insertAfter(point, ins_ldp);
        ChunkMutator(block).insertAfter(point, ins_bl);
        ChunkMutator(block).insertAfter(point, ins_mov);
        ChunkMutator(block).insertAfter(point, ins_stp);
    }
    else {
        ChunkMutator(block).insertBefore(point, ins_stp);
        ChunkMutator(block).insertBefore(point, ins_mov);
        ChunkMutator(block).insertBefore(point, ins_bl);
        ChunkMutator(block).insertBefore(point, ins_ldp);
    }
#endif
}
