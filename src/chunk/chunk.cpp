#include <sstream>
#include "chunk.h"
#include "transform/sandbox.h"

void Function::append(Block *block) {
    blockList.push_back(block);
    size += block->getSize();
    block->setOuter(this);

    std::ostringstream name;
    name << "bb" << blockList.size();
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
    instrList.push_back(instr);
    size += instr.getSize();
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

void Instruction::writeTo(Slot *slot) {
    slot->append(raw().bytes, raw().size);
}
