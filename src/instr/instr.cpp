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

void Instruction::setSize(size_t value) {
    semantic->setSize(value);
}

void Instruction::serialize(ChunkSerializerOperations &op,
    ArchiveStreamWriter &writer) {

#if 0
    writer.write(static_cast<uint64_t>(getAddress()));

    InstrWriterGetData instrWriter;
    getSemantic()->accept(&instrWriter);
    writer.writeAnyLength(instrWriter.get());
#endif
}

bool Instruction::deserialize(ChunkSerializerOperations &op,
    ArchiveStreamReader &reader) {

#if 0
    uint64_t address;
    reader.read(address);
    //setPosition(new AbsolutePosition(address));
    //setPosition(new AbsolutePosition(-1));

    std::string data;
    reader.readAnyLength(data);
#if 1
    static DisasmHandle handle(true);
    try {
        setSemantic(DisassembleInstruction(handle)
            .instructionSemantic(this, data, address));
    }
    catch(const char *what) {
        LOG(1, "DISASSEMBLY ERROR: " << what);
        RawByteStorage storage(data);
        setSemantic(new RawInstruction(std::move(storage)));
    }
#else
    RawByteStorage storage(data);
    setSemantic(new RawInstruction(std::move(storage)));
#endif
#endif

    return reader.stillGood();
}

void Instruction::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}
