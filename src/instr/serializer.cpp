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

enum EgalitoLinkType {
    TYPE_UNKNOWN_LINK = 0,
    TYPE_ExternalAbsoluteNormalLink,
    TYPE_ExternalNormalLink,
    TYPE_AbsoluteNormalLink,
    TYPE_NormalLink,
    TYPE_ExternalOffsetLink,
    TYPE_OffsetLink,
    TYPE_PLTLink,
    TYPE_JumpTableLink,
    TYPE_SymbolOnlyLink,
    TYPE_MarkerLink,
    TYPE_AbsoluteDataLink,
    TYPE_DataOffsetLink,
    TYPE_TLSDataOffsetLink,
    TYPE_UnresolvedLink,
    TYPE_ImmAndDispLink,
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
    virtual void visit(LinkedInstruction *linked);
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
private:
    void writeLink(Link *link);
    void writeLinkReference(Chunk *ref);
    void writeLinkTarget(Link *link);
};

void SemanticSerializer::write(EgalitoInstrType type,
    InstructionSemantic *forBytes) {

    writer.write(static_cast<uint8_t>(type));

    InstrWriterGetData instrWriter;
    forBytes->accept(&instrWriter);
    writer.writeAnyLength(instrWriter.get());
}

void SemanticSerializer::writeLink(Link *link) {
    if(auto v = dynamic_cast<ExternalAbsoluteNormalLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_ExternalAbsoluteNormalLink));
        writeLinkTarget(link);
    }
    else if(auto v = dynamic_cast<ExternalNormalLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_ExternalNormalLink));
        writeLinkTarget(link);
    }
    else if(auto v = dynamic_cast<AbsoluteNormalLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_AbsoluteNormalLink));
        writeLinkTarget(link);
    }
    else if(auto v = dynamic_cast<NormalLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_NormalLink));
        writeLinkTarget(link);
    }
    else if(auto v = dynamic_cast<ExternalOffsetLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_ExternalOffsetLink));
        auto target = link->getTarget();
        writeLinkReference(&*target);
        writer.write(link->getTargetAddress() - target->getAddress());
    }
    else if(auto v = dynamic_cast<OffsetLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_OffsetLink));
        auto target = link->getTarget();
        writeLinkReference(&*target);
        writer.write(link->getTargetAddress() - target->getAddress());
    }
    else if(auto v = dynamic_cast<PLTLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_PLTLink));
        writeLinkReference(v->getPLTTrampoline());
    }
    else if(auto v = dynamic_cast<JumpTableLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_JumpTableLink));

    }
    else if(auto v = dynamic_cast<SymbolOnlyLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_SymbolOnlyLink));

    }
    else if(auto v = dynamic_cast<MarkerLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_MarkerLink));

    }
    else if(auto v = dynamic_cast<AbsoluteDataLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_AbsoluteDataLink));

    }
    else if(auto v = dynamic_cast<DataOffsetLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_DataOffsetLink));
        auto section = link->getTarget();
        writeLinkReference(&*section);
        writer.write(link->getTargetAddress() - section->getAddress());
    }
    else if(auto v = dynamic_cast<TLSDataOffsetLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_TLSDataOffsetLink));

    }
    else if(auto v = dynamic_cast<UnresolvedLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_UnresolvedLink));

    }
    else if(auto v = dynamic_cast<ImmAndDispLink *>(link)) {
        writer.write(static_cast<uint8_t>(TYPE_ImmAndDispLink));

    }
    else {
        writer.write(static_cast<uint8_t>(TYPE_UNKNOWN_LINK));
    }
}

void SemanticSerializer::writeLinkReference(Chunk *ref) {
    FlatChunk::IDType id = static_cast<FlatChunk::IDType>(-1);
    if(ref) {
        id = op.assign(ref);
    }
    writer.write(static_cast<uint64_t>(id));
}

void SemanticSerializer::writeLinkTarget(Link *link) {
    auto target = &*link->getTarget();
    FlatChunk::IDType id = static_cast<FlatChunk::IDType>(-1);
    if(target) {
        id = op.assign(target);
    }
    writer.write(static_cast<uint64_t>(id));
}

void SemanticSerializer::visit(LinkedInstruction *linked) {
    write(TYPE_LinkedInstruction, linked);
    assert(linked->getLink());
    writeLink(linked->getLink());
    writer.write(static_cast<uint8_t>(linked->getIndex()));
}

void SemanticSerializer::visit(ControlFlowInstruction *controlFlow) {
    write(TYPE_ControlFlowInstruction, controlFlow);
    assert(controlFlow->getLink());
    writeLink(controlFlow->getLink());
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
        return defaultDeserialize(instruction, address, reader);
    case TYPE_LinkedInstruction: {
        auto semantic = defaultDeserialize(instruction, address, reader);
        auto semantic2 = new LinkedInstruction(instruction, *semantic->getAssembly());
        delete semantic;
        semantic2->setLink(deserializeLink(reader));
        uint8_t index;
        reader.read(index);
        semantic2->setIndex(index);
        return semantic2;
    }
    case TYPE_ReturnInstruction:
        return defaultDeserialize(instruction, address, reader);
    case TYPE_IndirectJumpInstruction:
        return defaultDeserialize(instruction, address, reader);
    case TYPE_IndirectCallInstruction:
        return defaultDeserialize(instruction, address, reader);
    case TYPE_StackFrameInstruction:
        throw "StackFrameInstruction?";
    case TYPE_LiteralInstruction:
        throw "LiteralInstruction?";
    case TYPE_LinkedLiteralInstruction: {
        return defaultDeserialize(instruction, address, reader);
    }
    case TYPE_ControlFlowInstruction: {
        auto semantic = defaultDeserialize(instruction, address, reader);
        semantic->setLink(deserializeLink(reader));
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

Link *InstrSerializer::deserializeLink(ArchiveStreamReader &reader) {
    uint8_t type;
    reader.read(type);

    switch(type) {
    case TYPE_ExternalAbsoluteNormalLink:
        return new ExternalAbsoluteNormalLink(deserializeLinkTarget(reader));
    case TYPE_ExternalNormalLink:
        return new ExternalNormalLink(deserializeLinkTarget(reader));
    case TYPE_AbsoluteNormalLink:
        return new AbsoluteNormalLink(deserializeLinkTarget(reader));
    case TYPE_NormalLink:
        return new NormalLink(deserializeLinkTarget(reader));
    case TYPE_ExternalOffsetLink: {
        auto target = deserializeLinkTarget(reader);
        address_t offset;
        reader.read(offset);
        return new ExternalOffsetLink(target, offset);
    }
    case TYPE_OffsetLink: {
        auto target = deserializeLinkTarget(reader);
        address_t offset;
        reader.read(offset);
        return new OffsetLink(target, offset);
    }
    case TYPE_PLTLink:
        return new PLTLink(0x0,
            dynamic_cast<PLTTrampoline *>(deserializeLinkTarget(reader)));
    case TYPE_JumpTableLink:
        throw "unsupported: deserialize JumpTableLink";
    case TYPE_SymbolOnlyLink:
        throw "unsupported: deserialize SymbolOnlyLink";
    case TYPE_MarkerLink:
        throw "unsupported: deserialize MarkerLink";
    case TYPE_AbsoluteDataLink:
        return new UnresolvedLink(0);
    case TYPE_DataOffsetLink: {
        auto section = dynamic_cast<DataSection *>(deserializeLinkTarget(reader));
        address_t offset;
        reader.read(offset);
        return new DataOffsetLink(section, offset);
    }
    case TYPE_TLSDataOffsetLink:
    case TYPE_UnresolvedLink:
    case TYPE_ImmAndDispLink:
    case TYPE_UNKNOWN_LINK:
    default:
        return new UnresolvedLink(0);
    }
}

Chunk *InstrSerializer::deserializeLinkTarget(ArchiveStreamReader &reader) {
    uint64_t id = 0;
    reader.read(id);
    if(id != static_cast<uint32_t>(-1)) {
        Chunk *target = op.lookup(id);
        if(!target->getPosition()) {
            target->setPosition(new AbsolutePosition(-1));
        }
        return target;
    }
    return nullptr;
}
