#include "pass/instrumentcalls.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "operation/mutator.h"

#ifdef ARCH_AARCH64
void InstrumentCallsPass::useStack(Function *function, FrameType *frame) {
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
    addAdvice(ins, entry, true);
}

void InstrumentCallsPass::addExitAdvice(Function *function, FrameType *frame) {
    for(auto ins : frame->getEpilogueInstrs()) {
        addAdvice(ins, exit, false);
    }
}

void InstrumentCallsPass::addAdvice(
    Instruction *point, Function *advice, bool after) {

    /* For an arbitrary cutpoint, the base register must be figured out
     * from the frame type. */
    const PhysicalRegister<AARCH64GPRegister> rSP(
        AARCH64GPRegister::SP, true);
    const PhysicalRegister<AARCH64GPRegister> rLR(
        AARCH64GPRegister::LR, true);
    const PhysicalRegister<AARCH64GPRegister> rFP(
        AARCH64GPRegister::FP, true);

    auto bin_stp = AARCH64InstructionBinary(0xA9000000 | 0 << 15 |
                                            rLR.encoding() << 10 |
                                            rSP.encoding() << 5 |
                                            rFP.encoding());
    auto bin_bl = AARCH64InstructionBinary(0x94000000);
    auto bin_ldp = AARCH64InstructionBinary(0xA9400000 | 0 << 15 |
                                            rLR.encoding() << 10 |
                                            rSP.encoding() << 5 |
                                            rFP.encoding());
    auto ins_stp = Disassemble::instruction(bin_stp.getVector());
    auto ins_bl = Disassemble::instruction(bin_bl.getVector());
    ins_bl->getSemantic()->setLink(new NormalLink(advice));
    auto ins_ldp = Disassemble::instruction(bin_ldp.getVector());

    auto block = point->getParent();

    if(after) {
        ChunkMutator(block).insertAfter(point, ins_ldp);
        ChunkMutator(block).insertAfter(point, ins_bl);
        ChunkMutator(block).insertAfter(point, ins_stp);
    }
    else {
        ChunkMutator(block).insertBefore(point, ins_stp);
        ChunkMutator(block).insertBefore(point, ins_bl);
        ChunkMutator(block).insertBefore(point, ins_ldp);
    }
}
#endif

