#include "switchcontext.h"
#include "analysis/frametype.h"
#include "disasm/disassemble.h"
#include "instr/register.h"
#include "operation/mutator.h"

void SwitchContextPass::useStack(Function *function, FrameType *frame) {
    addSaveContextAt(function, frame);

    for(auto ins : frame->getEpilogueInstrs()) {
        addRestoreContextAt(ins, frame);
    }
}

void SwitchContextPass::addSaveContextAt(Function *function, FrameType *frame) {
#ifdef ARCH_AARCH64
    Block *block = function->getChildren()->getIterable()->get(0);
    Instruction *point = block->getChildren()->getIterable()->get(0);

    const PhysicalRegister<AARCH64GPRegister> rSP(
        AARCH64GPRegister::R31, true);

    auto bin_mrs = AARCH64InstructionBinary(0xD53B4200  // NZCV
        | PhysicalRegister<AARCH64GPRegister>(
            AARCH64GPRegister::R19, true).encoding());
    auto ins_mrs = Disassemble::instruction(bin_mrs.getVector());
    ChunkMutator(point->getParent()).insertAfter(point, ins_mrs);

    auto bin_mrs2 = AARCH64InstructionBinary(0xD53B4420 // FPSR
        | PhysicalRegister<AARCH64GPRegister>(
            AARCH64GPRegister::R20, true).encoding());
    auto ins_mrs2 = Disassemble::instruction(bin_mrs2.getVector());
    ChunkMutator(point->getParent()).insertAfter(point, ins_mrs2);

    // R0 and R1 are saved by StackExtendPass
    size_t pos = 10;
    for(int r = AARCH64GPRegister::R21; r > AARCH64GPRegister::R2; r -= 2) {
        auto bin_stp = AARCH64InstructionBinary(0xA9000000 |
            pos << 1 << 15 |
            PhysicalRegister<AARCH64GPRegister>(r, true).encoding() << 10 |
            rSP.encoding() << 5 |
            PhysicalRegister<AARCH64GPRegister>(r-1, true).encoding());

        auto ins_stp = Disassemble::instruction(bin_stp.getVector());
        ChunkMutator(point->getParent()).insertAfter(point, ins_stp);
        --pos;
    }
#endif
}

void SwitchContextPass::addRestoreContextAt(
    Instruction *instruction, FrameType *frame) {

#ifdef ARCH_AARCH64
    const PhysicalRegister<AARCH64GPRegister> rSP(
        AARCH64GPRegister::R31, true);

    auto bin_msr = AARCH64InstructionBinary(0xD51B4200  // NZCV
        | PhysicalRegister<AARCH64GPRegister>(
            AARCH64GPRegister::R19, true).encoding());
    auto ins_msr = Disassemble::instruction(bin_msr.getVector());
    ChunkMutator(instruction->getParent()).insertBefore(instruction, ins_msr);

    auto bin_msr2 = AARCH64InstructionBinary(0xD51B4420 // FPSR
        | PhysicalRegister<AARCH64GPRegister>(
            AARCH64GPRegister::R20, true).encoding());
    auto ins_msr2 = Disassemble::instruction(bin_msr2.getVector());
    ChunkMutator(instruction->getParent()).insertBefore(instruction, ins_msr2);

    // R0 and R1 are restored by StackExtendPass
    //Instruction *top = nullptr;
    size_t pos = 1;
    for(int r = AARCH64GPRegister::R2; r < AARCH64GPRegister::R21; r += 2) {
        auto bin_ldp = AARCH64InstructionBinary(0xA9400000 |
            pos << 1 << 15 |
            PhysicalRegister<AARCH64GPRegister>(r+1, true).encoding() << 10 |
            rSP.encoding() << 5 |
            PhysicalRegister<AARCH64GPRegister>(r, true).encoding());

        auto ins_ldp = Disassemble::instruction(bin_ldp.getVector());
        //if(!top) top = ins_ldp;
        ChunkMutator(instruction->getParent()).insertBefore(
            instruction, ins_ldp);
        ++pos;
    }

    frame->fixEpilogue(instruction, ins_msr);
#endif
}
