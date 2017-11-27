#include <cassert>
#include "serializer.h"
#include "visitor.h"
#include "writer.h"
#include "concrete.h"
#include "disasm/disassemble.h"
#include "disasm/makesemantic.h"
#include "disasm/handle.h"
#include "chunk/serializer.h"
#include "log/log.h"

enum EgalitoInstrType {
    TYPE_UNKNOWN_INSTR = 0,
    TYPE_RawInstruction,
    TYPE_IsolatedInstruction,
    TYPE_LinkedInstruction,
    TYPE_ControlFlowInstruction,
    TYPE_ReturnInstruction,
    TYPE_IndirectJumpInstruction,
    TYPE_IndirectCallInstruction,
    TYPE_StackFrameInstruction,
    TYPE_LiteralInstruction,
    TYPE_LinkedLiteralInstruction,
};

class SemanticSerializer : public InstructionVisitor {
private:
    ChunkSerializerOperations &op;
    ArchiveStreamWriter &writer;
public:
    SemanticSerializer(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer) : op(op), writer(writer) {}
private:
    void write(EgalitoInstrType type, InstructionSemantic *forBytes);
public:
    virtual void visit(RawInstruction *raw)
        { write(TYPE_RawInstruction, raw); }
    virtual void visit(IsolatedInstruction *isolated)
        { write(TYPE_IsolatedInstruction, isolated); }
    virtual void visit(LinkedInstruction *linked)
        { write(TYPE_LinkedInstruction, linked); }
    virtual void visit(ControlFlowInstruction *controlFlow);
    virtual void visit(ReturnInstruction *retInstr)
        { write(TYPE_ReturnInstruction, retInstr); }
    virtual void visit(IndirectJumpInstruction *indirect)
        { write(TYPE_IndirectJumpInstruction, indirect); }
    virtual void visit(IndirectCallInstruction *indirect)
        { write(TYPE_IndirectCallInstruction, indirect); }
    virtual void visit(StackFrameInstruction *stackFrame)
        { write(TYPE_StackFrameInstruction, stackFrame); }
    virtual void visit(LiteralInstruction *literal)
        { write(TYPE_LiteralInstruction, literal); }
    virtual void visit(LinkedLiteralInstruction *literal)
        { write(TYPE_LinkedLiteralInstruction, literal); }
};

void SemanticSerializer::write(EgalitoInstrType type,
    InstructionSemantic *forBytes) {

    writer.write(static_cast<uint8_t>(type));

    InstrWriterGetData instrWriter;
    forBytes->accept(&instrWriter);
    writer.writeAnyLength(instrWriter.get());
}


void SemanticSerializer::visit(ControlFlowInstruction *controlFlow) {
    write(TYPE_ControlFlowInstruction, controlFlow);
    assert(controlFlow->getLink());

    auto target = &*controlFlow->getLink()->getTarget();
#if 0
    FlatChunk::IDType id;
    if(op.fetch(target, id)) {
        writer.write(static_cast<uint64_t>(id));
    }
    else writer.write(static_cast<uint64_t>(-1));
#else
    FlatChunk::IDType id = static_cast<FlatChunk::IDType>(-1);
    if(target) {
        LOG(1, "call instruction targets " << target->getName());
        id = op.assign(target);
    }
    writer.write(static_cast<uint64_t>(id));
#endif
}

void InstrSerializer::serialize(InstructionSemantic *semantic,
    ArchiveStreamWriter &writer) {

    SemanticSerializer ss(op, writer);
    semantic->accept(&ss);
}

InstructionSemantic *InstrSerializer::deserialize(Instruction *instruction,
    address_t address, ArchiveStreamReader &reader) {

    uint8_t type;
    reader.read(type);

    switch(static_cast<EgalitoInstrType>(type)) {
    case TYPE_RawInstruction:
    case TYPE_IsolatedInstruction:
    case TYPE_LinkedInstruction:
    case TYPE_ReturnInstruction:
    case TYPE_IndirectJumpInstruction:
    case TYPE_IndirectCallInstruction:
    case TYPE_StackFrameInstruction:
    case TYPE_LiteralInstruction:
    case TYPE_LinkedLiteralInstruction: {
        return defaultDeserialize(instruction, address, reader);
    }
    case TYPE_ControlFlowInstruction: {
        auto semantic = defaultDeserialize(instruction, address, reader);
        uint64_t id = 0;
        reader.read(id);
        if(id != static_cast<uint32_t>(-1)) {
            Chunk *target = op.lookup(id);
            if(!target->getPosition()) {
                target->setPosition(new AbsolutePosition(-1));
            }
            LOG(1, "call instruction targets " << target->getName());
            semantic->setLink(new NormalLink(target));
        }
        return semantic;
    }
    default:
        break;
    }

    LOG(1, "Unknown instruction type " << std::dec << static_cast<int>(type)
        << " in InstrSerializer::deserialize!");
    return nullptr;
}

InstructionSemantic *InstrSerializer::defaultDeserialize(Instruction *instruction,
    address_t address, ArchiveStreamReader &reader) {

    std::string bytes;
    reader.readAnyLength(bytes);
#if 1
    try {
        static DisasmHandle handle(true);
        auto semantic = DisassembleInstruction(handle, true)
            .instructionSemantic(instruction, bytes, address);
        return semantic;
    }
    catch(const char *what) {
        LOG(1, "DISASSEMBLY ERROR: " << what);
        RawByteStorage storage(bytes);
        return new RawInstruction(std::move(storage));
    }
#else
    RawByteStorage storage(bytes);
    return new RawInstruction(std::move(storage));
#endif
}
