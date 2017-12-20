#include "vtable.h"
#include "visitor.h"
#include "serializer.h"
#include "instr/serializer.h"

void VTableEntry::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write(getAddress());

    // we may not write anything if the Link is null
    if(link) {
        LinkSerializer(op).serialize(link, writer);
    }
}

bool VTableEntry::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    setPosition(PositionFactory::getInstance()
        ->makeAbsolutePosition(reader.read<address_t>()));

    link = LinkSerializer(op).deserialize(reader);

    return reader.stillGood();
}

void VTableEntry::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

std::string VTable::getName() const {
    return "vtable for " + className;
}

void VTable::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeString(className);
    op.serializeChildren(this, writer);
}

bool VTable::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    className = reader.readString();
    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void VTable::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void VTableList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    op.serializeChildren(this, writer);
}

bool VTableList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void VTableList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
