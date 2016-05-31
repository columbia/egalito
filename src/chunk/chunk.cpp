#include <iostream>  // for debugging
#include <sstream>
#include <cstring>  // for memcpy
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

void Function::sizeChanged(ssize_t bytesAdded, Block *which) {
    bool after = false;
    for(auto block : blockList) {
        if(after) {
            block->setOffset(block->getOffset() + bytesAdded);
        }
        else if(block == which) {
            after = true;
        }
    }
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

    if(outer) outer->sizeChanged(+ instr.getSize(), this);
}

address_t Block::getAddress() const {
    //std::cout << "block " << getName() << ", outer = " << outer << '\n';
    if(!outer) {
        throw "Can't get address of block outside a function";
    }
    return outer->getAddress() + offset;
}

void Block::sizeChanged(ssize_t bytesAdded) {
    size += bytesAdded;
}

void Block::setOffset(size_t offset) {
    this->offset = offset;

    size_t addr = 0;
    for(auto &instr : instrList) {
        instr.setOffset(addr);
        addr += instr.getSize();
    }
}

void Block::writeTo(Slot *slot) {
    for(auto &instr : instrList) {
        instr.writeTo(slot);
    }
}

void Instruction::regenerate() {
    if(!outer || !outer->getOuter()) return;

    std::string bytes;
    if(detail == DETAIL_CAPSTONE) {
        bytes.assign((char *)insn.bytes, insn.size);
        /*std::cout << "regenerate [";
        for(int i = 0; i < insn.size; i ++) std::cout << std::hex << ((unsigned)bytes[i] & 0xff) << " ";
        std::cout << "]\n";*/
    }
    else {
        bytes = data;
    }

    //std::cout << "regenerate at " << getAddress() << ", offset = " << outer->getOffset() << "\n";

    this->insn = Disassemble::getInsn(bytes, getAddress());
    detail = DETAIL_CAPSTONE;
}

address_t Instruction::getAddress() const {
    //if(detail == DETAIL_CAPSTONE) return insn.address;

    if(!outer) {
        throw "Can't get address of instruction outside a function";
    }
    return outer->getAddress() + offset;
}

size_t Instruction::getSize() const {
    if(detail == DETAIL_CAPSTONE) return insn.size;

    return data.size();
}

void Instruction::setOffset(size_t offset) {
    this->offset = offset;
    if(detail == DETAIL_CAPSTONE) {
        regenerate();
    }
}

void Instruction::writeTo(Slot *slot) {
    slot->append(raw().bytes, raw().size);
}

void Instruction::dump() {
    //std::cout << "block = " << outer << " ";
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
