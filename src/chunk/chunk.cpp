#include <iostream>  // for debugging
#include <sstream>
#include <cstring>  // for memcpy
#include <cassert>
#include "chunk.h"
#include "disassemble.h"
#include "transform/sandbox.h"

template class ChunkImpl<NormalPosition>;
template class ChunkImpl<RelativePosition>;
template class ChunkImpl<OriginalPosition>;

template class CompositeImpl<Block>;
template class CompositeImpl<Instruction>;

template class ChildImpl<Function>;
template class ChildImpl<Block>;

template <typename PositionType>
address_t ChunkImpl<PositionType>::getAddress() const {
    return position.get();
}

template <typename PositionType>
void ChunkImpl<PositionType>::setAddress(address_t address) {
    position.set(address);
}

template <typename ParentType>
void ChildImpl<ParentType>::invalidateSize() {
    if(getParent()) {
        getParent()->invalidateSize();
    }
}

template <typename PositionType>
size_t CompositeImpl<PositionType>::getSize() const {
    if(!size.isValid()) {
        size_t sum = 0;
        for(auto child : children()) {
            sum += child->getSize();
        }
        size.set(sum);
    }
    return size.get();
}

template <typename PositionType>
void CompositeImpl<PositionType>::setSize(size_t size) {
    this->size.set(size);
}

template <typename PositionType>
bool ChunkImpl<PositionType>::contains(address_t a) {
    auto base = getAddress();  // only get once for efficiency
    return a >= base && a < base + getSize();
}

template <typename PositionType>
bool ChunkImpl<PositionType>::contains(address_t a, size_t s) {
    auto base = getAddress();  // only get once for efficiency
    return a >= base && a + s <= base + getSize();
}

template <typename PositionType>
void ChunkImpl<PositionType>::setVersion(int version) {
    throw "This type of Chunk cannot be versioned";
}

void Function::append(Block *block) {
    children().push_back(block);
    block->setParent(this);
    block->setOffset(getSize());
    getCalculatedSize().add(block->getSize());

    std::ostringstream name;
    name << "bb" << children().size() << "-offset-" << block->getOffset();
    block->setName(name.str());
}

void Function::writeTo(Sandbox *sandbox) {
    getPosition().finalize();

    for(auto block : children()) {
        block->writeTo(sandbox);
    }
}

Instruction *Block::append(Instruction instr) {
    instr.setParent(this);
    instr.setOffset(getSize());
    getCalculatedSize().add(instr.getSize());

    auto i = new Instruction(instr);
    children().push_back(i);

    if(getParent()) getParent()->invalidateSize();
    return i;
}

void Block::invalidateSize() {
    CompositeImpl<Instruction>::invalidateSize();
    ChildImpl<Function>::invalidateSize();
}

void Block::writeTo(Sandbox *sandbox) {
    for(auto instr : children()) {
        instr->writeTo(sandbox);
    }
}

void NativeInstruction::regenerate() {
    auto address = instr->getAddress();
    insn = Disassemble::getInsn(instr->getRawData(), address);
}

cs_insn &NativeInstruction::raw() {
    if(!cached) regenerate();
    return insn;
}

Instruction::Instruction(std::string data, address_t originalAddress)
    : ChunkImpl<RelativePosition>(RelativePosition(nullptr, 0)), data(data),
    link(nullptr), native(this), originalAddress(originalAddress) {

    // nothing more to do
}

Instruction::Instruction(cs_insn insn)
    : ChunkImpl<RelativePosition>(RelativePosition(nullptr, insn.address)),
    link(nullptr), native(this, insn), originalAddress(insn.address) {

    data.assign((char *)insn.bytes, insn.size);
}

void Instruction::setParent(Block *parent) {
    ChildImpl<Block>::setParent(parent);
    native.invalidate();
}

void Instruction::setSize(size_t size) {
    throw "Cannot set the size of an Instruction directly";
}

void Instruction::invalidateSize() {
    throw "It is meaningless to invalidate the size of an Instruction";
}

#if 0
void Instruction::setOffset(size_t offset) {
    this->offset = offset;
    if(detail == DETAIL_CAPSTONE) {
        regenerate();
    }

    if(fixup) {
        if(detail == DETAIL_CAPSTONE) {
            data.assign((char *)insn.bytes, insn.size);
            //detail = DETAIL_NONE;
        }
        char *p = (char *)data.data();
        unsigned int *i = (unsigned int *)(p + 1);

        auto delta = -(getAddress() - originalAddress);
        delta += target->getTarget() - originalTarget;
        std::printf("target is %lx\n", target->getTarget());
        std::printf("ADJUST instruction from %lx to %lx by %lx\n",
            originalAddress, getAddress(), delta);
        *i += delta;
        originalAddress = getAddress();
        originalTarget = target->getTarget();

        if(detail == DETAIL_CAPSTONE) {
            std::memcpy((void *)insn.bytes, p, insn.size);
            regenerate();
        }

        dump();
    }
}
#endif

void Instruction::makeLink(address_t sourceOffset, Position *target) {
    this->link = new KnownSourceLink<RelativePosition>(
        RelativePosition(this, sourceOffset), target);
}

void Instruction::writeTo(Sandbox *sandbox) {
    throw "Supposed to implement Instruction::writeTo!!!";
    /*std::printf("append bytes to %lx\n", slot->getAddress());
    slot->append(raw().bytes, raw().size);*/
}

void Instruction::dump() {
    if(getParent() && getParent()->getParent()) {
        Disassemble::printInstructionAtOffset(&getNative(),
            getPosition().getOffset() + getParent()->getOffset());
    }
    else {
        Disassemble::printInstruction(&getNative());
    }
}
