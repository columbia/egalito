#include <string>
#include <sstream>
#include <iomanip>
#include "chunk/serializer.h"
#include "chunk/visitor.h"
#include "instr.h"
#include "serializer.h"
#include "semantic.h"
#include "writer.h"
#include "disasm/disassemble.h"
#include "log/log.h"

#include "isolated.h"  // for debugging

std::string Instruction::getName() const {
    std::ostringstream stream;
    if(getPosition()) {
        stream << "i/0x" << std::hex << getAddress();
    }
    else {
        stream << "i/???";
    }
    return stream.str();
}

size_t Instruction::getSize() const {
    return semantic->getSize();
}

void Instruction::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

    // not called for Functions, just for PLTTrampolines
#if 1
    writer.write(getAddress());
    writer.write(op.assign(getPreviousSibling() ? getPreviousSibling() : getParent()));

    InstrSerializer(op).serialize(getSemantic(), writer);
#endif
}

bool Instruction::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    // not called for Functions, just for PLTTrampolines
#if 1
    auto address = reader.read<address_t>();
    //setPosition(new AbsolutePosition(address));
    auto afterThis = op.lookup(reader.readID());
    setPosition(new SubsequentPosition(afterThis));

    auto semantic = InstrSerializer(op).deserialize(this, address, reader);
    setSemantic(semantic);
#endif

    return reader.stillGood();
}

void Instruction::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
