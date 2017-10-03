#include <string>
#include <sstream>
#include <iomanip>
#include "chunk/serializer.h"
#include "chunk/visitor.h"
#include "instr.h"
#include "semantic.h"
#include "log/log.h"

#include "isolated.h"  // for debugging

std::string Instruction::getName() const {
    std::ostringstream stream;
    stream << "i/0x" << std::hex << getAddress();
    return stream.str();
}

size_t Instruction::getSize() const {
    return semantic->getSize();
}

void Instruction::setSize(size_t value) {
    semantic->setSize(value);
}

void Instruction::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    writer.write(static_cast<uint64_t>(getAddress()));
    writer.writeAnyLength(getName());
}

bool Instruction::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    uint64_t address;
    reader.read(address);
    setPosition(new AbsolutePosition(address));

    std::string name;
    reader.readAnyLength(name);

    RawByteStorage storage(std::string("\xcc", 1));
    setSemantic(new RawInstruction(std::move(storage)));

    LOG(1, "deserializing instruction " << name);

    return reader.stillGood();
}

void Instruction::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
