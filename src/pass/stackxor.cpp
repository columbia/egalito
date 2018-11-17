#include <sstream>
#include "stackxor.h"
#include "disasm/disassemble.h"
#include "operation/mutator.h"
#include "instr/concrete.h"

void StackXOR::visit(Function *function) {
    auto block1 = function->getChildren()->getIterable()->get(0);
    Instruction *first = nullptr;
    if(block1->getChildren()->getIterable()->getCount() > 0) {
        first = block1->getChildren()->getIterable()->get(0);
    }
    addInstructions(block1, first, false);
    recurse(function);
}

void StackXOR::visit(Block *block) {
    recurse(block);
}

void StackXOR::visit(Instruction *instruction) {
    auto parent = dynamic_cast<Block *>(instruction->getParent());
#ifdef ARCH_X86_64
    auto s = instruction->getSemantic();
    if(dynamic_cast<ReturnInstruction *>(s)) {
        addInstructions(parent, instruction, true);
    }
    else if(auto v = dynamic_cast<ControlFlowInstruction *>(s)) {
        // not a call, but still external; must be tail recursion
        if(v->getMnemonic() != "callq" && s->getLink()->isExternalJump()) {
            addInstructions(parent, instruction, true);
        }
    }
    else if(auto v = dynamic_cast<IndirectJumpInstruction *>(s)) {
        if(!v->isForJumpTable()) {
            addInstructions(parent, instruction, true);
        }
    }
    else if(s->isControlFlow()) {
        // includes IndirectCallInstruction and DataLinkedControlFlowInstruction
        addInstructions(parent, instruction, true);
    }
#endif
}

void StackXOR::addInstructions(Block *block, Instruction *instruction,
    bool beforeJumpTo) {
#ifdef ARCH_X86_64
    /*
        0000000000000000 <xor_ret_addr>:
           0:   64 4c 8b 1c 25 28 00    mov    %fs:0x28,%r11
           7:   00 00
           9:   4c 31 1c 24             xor    %r11,(%rsp)
    */

    ChunkMutator mutator(block);
#ifdef USE_KEYSTONE
    std::stringstream ss;
    ss << "mov %fs:0x" << std::hex << xorOffset << ",%r11\nxor %r11,(%rsp)";

    mutator.insertBefore(instruction, Reassemble::instructions(ss.str()), beforeJumpTo);
#else
    mutator.insertBefore(instruction, Disassemble::instruction(
        {0x64, 0x4c, 0x8b, 0x1c, 0x25,
            (unsigned char)xorOffset, 0x00, 0x00, 0x00}));
    mutator.insertBefore(instruction, Disassemble::instruction(
        {0x4c, 0x31, 0x1c, 0x24}));
#endif

#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    /*
           0:   92800010        mov     x16, #0xffffffffffffffff        // #-1
           4:   ca1003de        eor     x30, x30, x16

            note: depending on the disassembler the first instruction might be
            shown as movn #0
     */
    ChunkMutator mutator(block);
    mutator.insertBefore(Disassemble::instruction(
        {0x10, 0x00, 0x80, 0x92}), instruction);
    mutator.insertBefore(Disassemble::instruction(
        {0xde, 0x03, 0x10, 0xca}), instruction);
#endif
}
