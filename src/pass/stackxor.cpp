#include "stackxor.h"
#include "disasm/disassemble.h"

void StackXOR::visit(Function *function) {
    addInstructions(function->getChildren()->getIterable()->get(0), 0);
    recurse(function);
}

void StackXOR::visit(Block *block) {
    recurse(block);
}

void StackXOR::visit(Instruction *instruction) {
    std::string bytes = instruction->getSemantic()->getData();
    if(bytes == "\xc3") {
        auto parent = dynamic_cast<Block *>(instruction->getParent());

        addInstructions(parent,
            parent->getChildren()->getIterable()->indexOf(instruction));
    }
}

void StackXOR::addInstructions(Block *block, size_t index) {
    /*   
        0000000000000000 <xor_ret_addr>:
           0:   64 4c 8b 1c 25 28 00    mov    %fs:0x28,%r11
           7:   00 00
           9:   4c 31 1c 24             xor    %r11,(%rsp)
    */

    insertAt(block, index, Disassemble::instruction(
        {0x64, 0x4c, 0x8b, 0x1c, 0x25,
            (unsigned char)xorOffset, 0x00, 0x00, 0x00}));
    insertAt(block, index + 1, Disassemble::instruction(
        {0x4c, 0x31, 0x1c, 0x24}));
}

void StackXOR::insertAt(Block *block, size_t index, Instruction *instr) {
    auto list = block->getChildren()->getIterable();
    if(index == 0) {
        instr->setPosition(new RelativePosition(instr, 0));
    }
    else {
        instr->setPosition(
            new SubsequentPosition(list->get(index - 1)));

    }

    if(index < block->getChildren()->getIterable()->getCount()) {
        list->get(index)->setPosition(new SubsequentPosition(instr));
    }

    list->insertAt(index, instr);
    instr->setParent(block);
    block->addToSize(instr->getSize());
}
