#include "initfunction.h"
#include "function.h"
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
    writer.writeID(op.assign(specialCase));
    op.serializeChildren(this, writer);
}

bool InitFunctionList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    isInit = reader.read<bool>();
    setSpecialCaseFunction(op.lookupAs<Function>(reader.readID()));
    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

std::string InitFunctionList::getName() const {
    return isInit ? "initfunctionlist" : "finifunctionlist";
}

void InitFunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
