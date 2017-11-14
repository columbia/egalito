#include "serializer.h"
#include "visitor.h"
#include "disasm/makesemantic.h"
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
    ArchiveStreamWriter &writer;
public:
    SemanticSerializer(ArchiveStreamWriter &writer) : writer(writer) {}
private:
    void write(EgalitoInstrType type, InstructionSemantic *forBytes);
public:
    virtual void visit(RawInstruction *raw)
        { write(TYPE_RawInstruction, raw); }
    virtual void visit(IsolatedInstruction *isolated)
        { write(TYPE_IsolatedInstruction, isolated); }
    virtual void visit(LinkedInstruction *linked)
        { write(TYPE_LinkedInstruction, linked); }
    virtual void visit(ControlFlowInstruction *controlFlow)
        { write(TYPE_ControlFlowInstruction, controlFlow); }
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

void InstrSerializer::write(EgalitoInstrType type,
    InstructionSemantic *forBytes) {

    writer.write(static_cast<uint8_t>(type));

    InstrWriterGetData instrWriter;
    forBytes->getSemantic()->accept(&instrWriter);
    writer.writeAnyLength(instrWriter.get());
}

void InstrSerializer::serialize(InstructionSemantic *semantic,
    ArchiveStreamWriter &writer) {

    SemanticSerializer ss(writer);
    semantic->accept(&ss);
}

InstructionSemantic *InstrSerializer::deserialize(Instruction *instruction,
    ArchiveStreamReader &reader) {

    uint8_t type;
    reader.read(type);

    switch(static_cast<EgalitoInstrType>(type)) {
    case TYPE_RawInstruction:
    case TYPE_IsolatedInstruction:
    case TYPE_LinkedInstruction:
    case TYPE_ControlFlowInstruction:
    case TYPE_ReturnInstruction:
    case TYPE_IndirectJumpInstruction:
    case TYPE_IndirectCallInstruction:
    case TYPE_StackFrameInstruction:
    case TYPE_LiteralInstruction:
    case TYPE_LinkedLiteralInstruction: {
        return defaultDeserialize(instruction, address, reader);
    }
    default:
        break;
    }

    LOG(1, "Unknown instruction type in InstrSerializer::deserialize!");
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
        instr = new Instruction();
        RawByteStorage storage(bytes);
        return new RawInstruction(std::move(storage));
    }
#else
    RawByteStorage storage(bytes);
    return new RawInstruction(std::move(storage));
#endif
}
