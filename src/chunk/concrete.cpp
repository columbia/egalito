#include <sstream>
#include <iomanip>
#include "concrete.h"

Function *ChunkFactory::makeFunction(Symbol *symbol) {
    return new Function(symbol);
}

std::string Module::getName() const {
    std::ostringstream stream;
    auto count = getChildren()->getIterable()->getCount();
    stream << "module-" << count << "-functions";
    return stream.str();
}

std::string Block::getName() const {
    std::ostringstream stream;
    if(getParent() && getParent()->getName() != "???") {
        stream << getParent()->getName() << "/";
    }
    if(auto p = dynamic_cast<RelativePosition *>(getPosition())) {
        stream << "bb+" << p->getOffset();
    }
    return stream.str();
}

std::string Instruction::getName() const {
    std::ostringstream stream;
    stream << "i/0x" << std::hex << getAddress();
    return stream.str();
}

#if 0
void Function::append(Block *block) {
    size_t oldSize = getSize();
    children().push_back(block);
    block->setParent(this);
    block->setOffset(oldSize);
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

Instruction *Block::append(Instruction *instr) {
    instr->setParent(this);
    instr->setOffset(getSize());
    getCalculatedSize().add(instr->getSize());

    children().push_back(instr);

    if(getParent()) getParent()->invalidateSize();
    return instr;
}

void Block::setParent(Function *parent) {
    ChildImpl<Function>::setParent(parent);
    getPosition().setRelativeTo(this);
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
#if 0
    if(instr->hasRelativeTo()) {
        Disassemble::relocateInstruction(&insn, instr->getAddress());
    }
#else
    if(instr->getParent()) {
        auto address = instr->getAddress();
        insn = Disassemble::getInsn(instr->getRawData(), address);
        //cached = true;
    }
#endif
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
#if 0
    throw "Supposed to implement Instruction::writeTo!!!";
#else
    native.regenerate();
    auto address = getAddress();
    std::memcpy((void *)address, data.data(), data.size());
#endif

    //std::printf("append bytes to %lx\n", address);
    //slot->append(raw().bytes, raw().size);
}

void Instruction::dump() {
    if(getParent() && getParent()->getParent()) {
        const char *name = 0;
        if(hasLink()) {
            auto pos = dynamic_cast<RelativePosition *>(
                link->getTarget());
            if(pos) name = pos->getRelativeTo()->getName().c_str();
        }

        Disassemble::printInstruction(&getNative(),
            getPosition().getOffset() + getParent()->getOffset(),
            name);
    }
    else {
        Disassemble::printInstruction(&getNative());
    }
}
#endif
