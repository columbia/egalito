#include <cassert>
#include "program.h"
#include "visitor.h"
#include "serializer.h"
#include "log/log.h"

Program::Program(ElfSpaceList *spaceList) : main(nullptr), egalito(nullptr),
    spaceList(spaceList), entryPoint(nullptr) {

}

void Program::add(Module *module) {
    getChildren()->add(module);
}

void Program::setMain(Module *module) {
    this->main = module;
}

void Program::setEgalito(Module *module) {
    this->egalito = module;
}

address_t Program::getEntryPointAddress() {
    assert(entryPoint != nullptr);
    return entryPoint->getAddress();
}

void Program::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    LOG(1, "entry point is " << entryPoint);
    writer.write(op.assign(entryPoint));
    //writer.write(static_cast<FlatChunk::IDType>(-1));

    op.serializeChildren(this, writer);
    LOG(1, "done serializing program");
}

bool Program::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    FlatChunk::IDType id;
    reader.read(id);
    entryPoint = op.lookup(id);

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void Program::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
