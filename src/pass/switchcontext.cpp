#include "pass/switchcontext.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "operation/mutator.h"

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
void SwitchContextPass::useStack(Function *function, FrameType *frame) {
    addSaveContextAt(function, frame);

    for(auto ins : frame->getEpilogueInstrs()) {
        addRestoreContextAt(ins, frame);
    }
}

void SwitchContextPass::addSaveContextAt(Function *function, FrameType *frame) {
    /* Add something like this:
        __asm__ (
            "stp    x15, x14, [sp, #-(8*16)]!\n"
            "stp    x13, x12, [sp, #(1*16)]\n"
            "stp    x11, x10, [sp, #(2*16)]\n"
            "stp    x9,  x8,  [sp, #(3*16)]\n"
            "stp    x7,  x6,  [sp, #(4*16)]\n"
            "stp    x5,  x4,  [sp, #(5*16)]\n"
            "stp    x3,  x2,  [sp, #(6*16)]\n"
            "stp    x1,  x0,  [sp, #(7*16)]\n"
        );
    */
    const PhysicalRegister<AARCH64GPRegister> rSP(
        AARCH64GPRegister::R31, true);

    Block *block = function->getChildren()->getIterable()->get(0);
    Instruction *point = block->getChildren()->getIterable()->get(0);

    size_t pos = 0;
    for(auto r = AARCH64GPRegister::R0; r < AARCH64GPRegister::R16; ++r, ++pos) {
        auto firstR = PhysicalRegister<AARCH64GPRegister>(r, true);
        ++r;
        auto secondR = PhysicalRegister<AARCH64GPRegister>(r, true);

        auto bin_stp = AARCH64InstructionBinary(0xA9000000 |
            pos << 1 << 15 |
            secondR.encoding() << 10 |
            rSP.encoding() << 5 |
            firstR.encoding());

        auto ins_stp = Disassemble::instruction(bin_stp.getVector());
        ChunkMutator(point->getParent()).insertAfter(point, ins_stp);
    }
}

void SwitchContextPass::addRestoreContextAt(
    Instruction *instruction, FrameType *frame) {
    /* Add something like this:
        __asm__ (
            "ldp    x1,  x0,  [sp, #(7*16)]\n"
            "ldp    x3,  x2,  [sp, #(6*16)]\n"
            "ldp    x5,  x4,  [sp, #(5*16)]\n"
            "ldp    x7,  x6,  [sp, #(4*16)]\n"
            "ldp    x9,  x8,  [sp, #(3*16)]\n"
            "ldp    x11, x10, [sp, #(2*16)]\n"
            "ldp    x13, x12, [sp, #(1*16)]\n"
            "ldp    x15, x14, [sp],#-(8*16)\n"
        );
    */

    const PhysicalRegister<AARCH64GPRegister> rSP(
        AARCH64GPRegister::R31, true);

    Instruction *top;

    size_t pos = 0;
    for(auto r = AARCH64GPRegister::R0; r < AARCH64GPRegister::R16; ++r, ++pos) {
        auto firstR = PhysicalRegister<AARCH64GPRegister>(r, true);
        ++r;
        auto secondR = PhysicalRegister<AARCH64GPRegister>(r, true);

        auto bin_ldp = AARCH64InstructionBinary(0xA9400000 |
            pos << 1 << 15 |
            secondR.encoding() << 10 |
            rSP.encoding() << 5 |
            firstR.encoding());

        auto ins_ldp = Disassemble::instruction(bin_ldp.getVector());
        top = ins_ldp;
        ChunkMutator(instruction->getParent()).insertBefore(instruction, ins_ldp);
    }
    frame->fixEpilogue(instruction, top);
}
#endif
