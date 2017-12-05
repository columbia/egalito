#include <cassert>
#include "jumptable.h"
#include "serializer.h"
#include "visitor.h"
#include "analysis/jumptable.h"
#include "instr/concrete.h"
#include "instr/serializer.h"
#include "elf/elfmap.h"
#include "log/log.h"

void JumpTableEntry::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    // we may not write anything if the Link is null
    if(link) {
        LinkSerializer(op).serialize(link, writer);
    }
}

bool JumpTableEntry::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    link = LinkSerializer(op).deserialize(reader);

    return true;  // success even if no Link was read
}

void JumpTableEntry::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

JumpTable::JumpTable(ElfMap *elf, JumpTableDescriptor *descriptor)
    : descriptor(descriptor) {

    setPosition(PositionFactory::getInstance()
        ->makeAbsolutePosition(descriptor->getAddress()));
}

Function *JumpTable::getFunction() const {
    return descriptor->getFunction();
}

std::vector<Instruction *> JumpTable::getJumpInstructionList() const {
    return jumpInstrList;
}

long JumpTable::getEntryCount() const {
    return descriptor->getEntries();
}

void JumpTable::addJumpInstruction(Instruction *instr) {
    jumpInstrList.push_back(instr);

    auto v = dynamic_cast<IndirectJumpInstruction *>(instr->getSemantic());
    assert(v != nullptr);

    v->addJumpTable(this);
    LOG(10, "OK, instr " << instr->getName()
        << " knows about jump table: " << this);
}

void JumpTable::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeID(op.assign(descriptor->getFunction()));
    writer.writeID(op.assign(descriptor->getInstruction()));
    writer.write(descriptor->getAddress());
    writer.write(descriptor->getTargetBaseAddress());
    // do not serialize indexExpr
    writer.write<uint32_t>(descriptor->getIndexRegister());
    writer.write<uint8_t>(descriptor->getScale());
    writer.write<uint64_t>(descriptor->getBound());

    op.serializeChildren(this, writer);
    writer.write<uint32_t>(jumpInstrList.size());
    for(auto instr : jumpInstrList) {
        writer.writeID(op.assign(instr));
    }
}

bool JumpTable::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    auto function       = op.lookupAs<Function>(reader.readID());
    auto instruction    = op.lookupAs<Instruction>(reader.readID());
    auto address        = reader.read<address_t>();
    auto targetBaseAddress = reader.read<address_t>();
    // do not deserialize indexExpr
    auto reg            = reader.read<uint32_t>();
    auto scale          = reader.read<uint8_t>();
    auto bound          = reader.read<uint64_t>();

    descriptor = new JumpTableDescriptor(function, instruction);
    descriptor->setAddress(address);
    descriptor->setTargetBaseAddress(targetBaseAddress);
    descriptor->setIndexRegister(static_cast<Register>(reg));
    descriptor->setScale(scale);
    descriptor->setBound(bound);

    setPosition(new AbsolutePosition(address));

    op.deserializeChildren(this, reader);
    auto instrCount = reader.read<uint32_t>();
    for(uint32_t i = 0; i < instrCount; i ++) {
        auto instr = op.lookupAs<Instruction>(reader.readID());
        jumpInstrList.push_back(instr);
    }
    return reader.stillGood();
}

void JumpTable::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void JumpTableList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    op.serializeChildren(this, writer);
}

bool JumpTableList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void JumpTableList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
