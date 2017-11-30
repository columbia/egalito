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

// this is only a separate class to implement a Visitor
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
};

void SemanticSerializer::write(EgalitoInstrType type,
    InstructionSemantic *forBytes) {

    writer.write<uint8_t>(type);

    InstrWriterGetData instrWriter;
    forBytes->accept(&instrWriter);
    writer.writeBytes<uint8_t>(instrWriter.get());
}

void SemanticSerializer::visit(LinkedInstruction *linked) {
    write(TYPE_LinkedInstruction, linked);
    assert(linked->getLink());
    LinkSerializer(op).serialize(linked->getLink(), writer);
    writer.write<uint8_t>(linked->getIndex());
}

void SemanticSerializer::visit(ControlFlowInstruction *controlFlow) {
    write(TYPE_ControlFlowInstruction, controlFlow);
    assert(controlFlow->getLink());
    LinkSerializer(op).serialize(controlFlow->getLink(), writer);
}

void InstrSerializer::serialize(InstructionSemantic *semantic,
    ArchiveStreamWriter &writer) {

    SemanticSerializer ss(op, writer);
    semantic->accept(&ss);
}

InstructionSemantic *InstrSerializer::deserialize(Instruction *instruction,
    address_t address, ArchiveStreamReader &reader) {

    auto type = reader.read<uint8_t>();

    switch(static_cast<EgalitoInstrType>(type)) {
    case TYPE_RawInstruction:
    case TYPE_IsolatedInstruction:
        return defaultDeserialize(instruction, address, reader);
    case TYPE_LinkedInstruction: {
        auto semantic = defaultDeserialize(instruction, address, reader);
        auto semantic2 = new LinkedInstruction(instruction, *semantic->getAssembly());
        delete semantic;
        semantic2->setLink(LinkSerializer(op).deserialize(reader));
        semantic2->setIndex(reader.read<uint8_t>());
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
        semantic->setLink(LinkSerializer(op).deserialize(reader));
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

    std::string bytes = reader.readBytes<uint8_t>();
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

void LinkSerializer::serialize(Link *link, ArchiveStreamWriter &writer) {
    if(dynamic_cast<ExternalAbsoluteNormalLink *>(link)) {
        writer.write<uint8_t>(TYPE_ExternalAbsoluteNormalLink);
        writer.writeID(op.assign(&*link->getTarget()));
    }
    else if(dynamic_cast<ExternalNormalLink *>(link)) {
        writer.write<uint8_t>(TYPE_ExternalNormalLink);
        writer.writeID(op.assign(&*link->getTarget()));
    }
    else if(dynamic_cast<AbsoluteNormalLink *>(link)) {
        writer.write<uint8_t>(TYPE_AbsoluteNormalLink);
        writer.writeID(op.assign(&*link->getTarget()));
    }
    else if(dynamic_cast<NormalLink *>(link)) {
        writer.write<uint8_t>(TYPE_NormalLink);
        writer.writeID(op.assign(&*link->getTarget()));
    }
    else if(dynamic_cast<ExternalOffsetLink *>(link)) {
        writer.write<uint8_t>(TYPE_ExternalOffsetLink);
        auto target = link->getTarget();
        writer.writeID(op.assign(&*target));
        writer.write(link->getTargetAddress() - target->getAddress());
    }
    else if(dynamic_cast<OffsetLink *>(link)) {
        writer.write<uint8_t>(TYPE_OffsetLink);
        auto target = link->getTarget();
        writer.writeID(op.assign(&*target));
        writer.write(link->getTargetAddress() - target->getAddress());
    }
    else if(auto v = dynamic_cast<PLTLink *>(link)) {
        writer.write<uint8_t>(TYPE_PLTLink);
        writer.writeID(op.assign(v->getPLTTrampoline()));
    }
    else if(dynamic_cast<JumpTableLink *>(link)) {
        writer.write<uint8_t>(TYPE_JumpTableLink);

    }
    else if(dynamic_cast<SymbolOnlyLink *>(link)) {
        writer.write<uint8_t>(TYPE_SymbolOnlyLink);

    }
    else if(dynamic_cast<MarkerLink *>(link)) {
        writer.write<uint8_t>(TYPE_MarkerLink);
        LOG(0, "MarkerLink to " << link->getTargetAddress());
    }
    else if(dynamic_cast<AbsoluteDataLink *>(link)) {
        writer.write<uint8_t>(TYPE_AbsoluteDataLink);
        auto section = link->getTarget();
        writer.writeID(op.assign(&*section));
        writer.write(link->getTargetAddress() - section->getAddress());
    }
    else if(dynamic_cast<DataOffsetLink *>(link)) {
        writer.write<uint8_t>(TYPE_DataOffsetLink);
        auto section = link->getTarget();
        writer.writeID(op.assign(&*section));
        writer.write(link->getTargetAddress() - section->getAddress());
    }
    else if(dynamic_cast<TLSDataOffsetLink *>(link)) {
        writer.write<uint8_t>(TYPE_TLSDataOffsetLink);

    }
    else if(dynamic_cast<UnresolvedLink *>(link)) {
        writer.write<uint8_t>(TYPE_UnresolvedLink);

    }
    else if(dynamic_cast<ImmAndDispLink *>(link)) {
        writer.write<uint8_t>(TYPE_ImmAndDispLink);

    }
    else {
        writer.write<uint8_t>(TYPE_UNKNOWN_LINK);
    }
}

Link *LinkSerializer::deserialize(ArchiveStreamReader &reader) {
    auto type = reader.read<uint8_t>();
    if(!reader.stillGood()) return nullptr;

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
        auto offset = reader.read<address_t>();
        return new ExternalOffsetLink(target, offset);
    }
    case TYPE_OffsetLink: {
        auto target = deserializeLinkTarget(reader);
        auto offset = reader.read<address_t>();
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
        return new UnresolvedLink(0);  // unsupported
    case TYPE_AbsoluteDataLink: {
        auto section = dynamic_cast<DataSection *>(deserializeLinkTarget(reader));
        auto offset = reader.read<address_t>();
        return new AbsoluteDataLink(section, offset);
    }
    case TYPE_DataOffsetLink: {
        auto section = dynamic_cast<DataSection *>(deserializeLinkTarget(reader));
        auto offset = reader.read<address_t>();
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

Chunk *LinkSerializer::deserializeLinkTarget(ArchiveStreamReader &reader) {
    auto id = reader.readID();  // can be NoneID
    Chunk *target = op.lookup(id);  // can be nullptr
    if(target && !target->getPosition()) {
        target->setPosition(new AbsolutePosition(-1));
    }
    return target;
}
