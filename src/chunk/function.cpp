#include <sstream>
#include <iomanip>
#include "function.h"
#include "serializer.h"
#include "visitor.h"
#include "elf/symbol.h"
#include "log/log.h"

Function::Function(address_t originalAddress) : symbol(nullptr) {
    std::ostringstream stream;
    stream << "fuzzyfunc-0x" << std::hex << originalAddress;
    name = stream.str();
}

Function::Function(Symbol *symbol) : symbol(symbol) {
    name = symbol->getName();
}

bool Function::hasName(std::string name) const {
    if(symbol->getName() == name) return true;
    for(auto s : getSymbol()->getAliases()) {
        if(std::string(s->getName()) == name) {
            return true;
        }
    }

    return false;
}

void Function::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    LOG(1, "serialize function " << getName());

    writer.write(static_cast<uint64_t>(getAddress()));
    writer.writeAnyLength(getName());
    op.serializeChildren(this, writer);

    LOG(1, "...returning from serialize function " << getName());
}

bool Function::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    uint64_t address;
    std::string name;
    reader.read(address);
    reader.readAnyLength(name);

    setPosition(new AbsolutePosition(address));
    setName(name);

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void Function::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void FunctionList::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    op.serializeChildren(this, writer);
}

bool FunctionList::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    op.deserializeChildren(this, reader);
    return reader.stillGood();
}

void FunctionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
