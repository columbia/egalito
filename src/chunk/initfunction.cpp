#include "initfunction.h"
#include "function.h"
#include "serializer.h"
#include "visitor.h"
#include "log/log.h"

InitFunction::InitFunction(bool init, DataVariable *dataVariable)
    : init(init), specialCase(false), function(nullptr), dataVariable(dataVariable) {

    if(auto v = dynamic_cast<Function *>(dataVariable->getDest()->getTarget())) {
        function = v;
    }
    else if(auto v = dynamic_cast<Instruction *>(dataVariable->getDest()->getTarget())) {
        function = static_cast<Function *>(v->getParent()->getParent());
    }
    else {
        LOG(0, "ERROR: Init function pointing at unknown Chunk type!");
    }
}

void InitFunction::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write<bool>(init);
    writer.write<bool>(specialCase);
    writer.writeID(op.assign(function));
    writer.writeID(op.assign(dataVariable));
    op.serializeChildren(this, writer);
}

bool InitFunction::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    init = reader.read<bool>();
    specialCase = reader.read<bool>();
    function = op.lookupAs<Function>(reader.readID());
    dataVariable = op.lookupAs<DataVariable>(reader.readID());
    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void InitFunction::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void InitFunctionList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write<bool>(init);
    writer.writeID(op.assign(specialCase));
    op.serializeChildren(this, writer);
}

bool InitFunctionList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    init = reader.read<bool>();
    setSpecialCase(op.lookupAs<InitFunction>(reader.readID()));
    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

std::string InitFunctionList::getName() const {
    return init ? "initfunctionlist" : "finifunctionlist";
}

void InitFunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
