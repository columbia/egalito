#include <string>
#include <sstream>
#include <iomanip>
#include "chunk/serializer.h"
#include "chunk/visitor.h"
#include "instr.h"
#include "semantic.h"
#include "writer.h"
#include "disasm/disassemble.h"
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

    InstrWriterGetData instrWriter;
    getSemantic()->accept(&instrWriter);
    writer.writeAnyLength(instrWriter.get());
}

bool Instruction::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

    uint64_t address;
    reader.read(address);
    setPosition(new AbsolutePosition(address));

    std::string name;
    reader.readAnyLength(name);

    std::string data;
    reader.readAnyLength(data);
    DisasmHandle handle(true);
    try {
        setSemantic(DisassembleInstruction(handle)
            .instructionSemantic(this, data, address));
    }
    catch(const char *what) {
        LOG(1, "DISASSEMBLY ERROR: " << what);
        RawByteStorage storage(data);
        setSemantic(new RawInstruction(std::move(storage)));
    }

    return reader.stillGood();
}

void Instruction::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
