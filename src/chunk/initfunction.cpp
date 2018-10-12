#include "initfunction.h"
#include "serializer.h"
#include "visitor.h"

void InitFunction::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.writeID(op.assign(functionPointer));
    op.serializeChildren(this, writer);
}

bool InitFunction::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    functionPointer = op.lookupAs<DataVariable>(reader.readID());
    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void InitFunction::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void InitFunctionList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write<bool>(isInit);
    op.serializeChildren(this, writer);
}

bool InitFunctionList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    isInit = reader.read<bool>();
    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void InitFunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
