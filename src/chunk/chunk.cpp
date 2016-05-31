#include <iostream>  // for debugging
#include <sstream>
#include "chunk.h"
#include "disassemble.h"
#include "transform/sandbox.h"

void Function::append(Block *block) {
    blockList.push_back(block);
    block->setOuter(this);
    block->setOffset(size);
    size += block->getSize();

    std::ostringstream name;
    name << "bb" << blockList.size() << "-offset-" << block->getOffset();
    block->setName(name.str());
}

void Function::sizeChanged(ssize_t bytesAdded) {
    size += bytesAdded;
}

void Function::writeTo(Slot *slot) {
    for(auto block : blockList) {
        block->writeTo(slot);
    }
}

void Block::append(Instruction instr) {
    instr.setOuter(this);
    instr.setOffset(size);
    size += instr.getSize();
    instrList.push_back(instr);

    if(outer) outer->sizeChanged(+ instr.getSize());
}

address_t Block::getAddress() const {
    if(!outer) {
        throw "Can't get address of block outside a function";
    }
    return outer->getAddress() + offset;
}

void Block::sizeChanged(ssize_t bytesAdded) {
    size += bytesAdded;
}

void Block::writeTo(Slot *slot) {
    for(auto instr : instrList) {
        instr.writeTo(slot);
    }
}

address_t Instruction::getAddress() const {
    if(detail == DETAIL_CAPSTONE) return insn.address;

    if(!outer) {
        throw "Can't get address of instruction outside a function";
    }
    return outer->getAddress() + offset;
}

size_t Instruction::getSize() const {
    if(detail == DETAIL_CAPSTONE) return insn.size;

    return data.size();
}

void Instruction::writeTo(Slot *slot) {
    slot->append(raw().bytes, raw().size);
}

void Instruction::dump() {
    cs_insn i;
    if(detail == DETAIL_CAPSTONE) {
        i = insn;
    }
    else {
        i = Disassemble::getInsn(data.data(), getAddress());
    }

    if(outer && outer->getOuter()) {
        Disassemble::printInstructionAtOffset(&i,
            offset + outer->getOffset());
    }
    else {
        Disassemble::printInstruction(&i);
    }
}
