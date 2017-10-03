#include "program.h"
#include "visitor.h"
#include "serializer.h"
#include "log/log.h"

Program::Program(ElfSpaceList *spaceList)
    : main(nullptr), egalito(nullptr), spaceList(spaceList) {

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

void Program::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    op.serializeChildren(this, writer);
    LOG(1, "done serializing program");
}

bool Program::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void Program::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
