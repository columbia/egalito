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
    TYPE_IsolatedInstruction,
    TYPE_LinkedInstruction,
    TYPE_ControlFlowInstruction,
    TYPE_DataLinkedControlFlowInstruction,
    TYPE_ReturnInstruction,
    TYPE_IndirectJumpInstruction,
    TYPE_IndirectCallInstruction,
    TYPE_StackFrameInstruction,
    TYPE_LiteralInstruction,
    TYPE_LinkedLiteralInstruction,
};

enum EgalitoLinkType {
    TYPE_UNKNOWN_LINK = 0,
    TYPE_AbsoluteNormalLink,
    TYPE_NormalLink,
    TYPE_OffsetLink,
    TYPE_PLTLink,
    TYPE_JumpTableLink,
    TYPE_EgalitoLoaderLink,
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
    virtual void visit(IsolatedInstruction *isolated)
        { write(TYPE_IsolatedInstruction, isolated); }
    virtual void visit(LinkedInstruction *linked);
    virtual void visit(ControlFlowInstruction *controlFlow);
#ifdef ARCH_X86_64
    virtual void visit(DataLinkedControlFlowInstruction *controlFlow);
#endif
    virtual void visit(ReturnInstruction *retInstr)
        { write(TYPE_ReturnInstruction, retInstr); }
    virtual void visit(IndirectJumpInstruction *indirect);
    virtual void visit(IndirectCallInstruction *indirect);
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
#ifdef ARCH_X86_64
    writer.write<uint8_t>(linked->getIndex());
#endif
}

void SemanticSerializer::visit(ControlFlowInstruction *controlFlow) {
    writer.write<uint8_t>(TYPE_ControlFlowInstruction);
#ifdef ARCH_X86_64
    writer.write<uint32_t>(controlFlow->getId());
#endif
    writer.writeID(op.assign(controlFlow->getSource()));
#ifdef ARCH_X86_64
    writer.writeBytes<uint8_t>(controlFlow->getOpcode());
#endif
    writer.writeString(controlFlow->getMnemonic());
#ifdef ARCH_X86_64
    writer.write<uint8_t>(controlFlow->getDisplacementSize());
#endif
    writer.write<bool>(controlFlow->returns());

    assert(controlFlow->getLink());
    LinkSerializer(op).serialize(controlFlow->getLink(), writer);
}

#ifdef ARCH_X86_64
void SemanticSerializer::visit(DataLinkedControlFlowInstruction *controlFlow) {
    writer.write<uint8_t>(TYPE_DataLinkedControlFlowInstruction);
    assert(controlFlow->getLink());
    LinkSerializer(op).serialize(controlFlow->getLink(), writer);
    writer.write<uint8_t>(controlFlow->getIndex());
    writer.write<bool>(controlFlow->getIsRelative());
}
#endif

void SemanticSerializer::visit(IndirectJumpInstruction *indirect) {
    writer.write<uint8_t>(TYPE_IndirectJumpInstruction);
    writer.writeString(indirect->getMnemonic());
    writer.write<uint8_t>(indirect->getRegister());

    InstrWriterGetData instrWriter;
    indirect->accept(&instrWriter);
    writer.writeBytes<uint8_t>(instrWriter.get());

    writer.write<uint32_t>(indirect->getJumpTables().size());
    for(auto jumpTable : indirect->getJumpTables()) {
        writer.writeID(op.assign(jumpTable));
    }
}

void SemanticSerializer::visit(IndirectCallInstruction *indirect) {
    writer.write<uint8_t>(TYPE_IndirectCallInstruction);
    writer.write<uint32_t>(indirect->getRegister());

    InstrWriterGetData instrWriter;
    indirect->accept(&instrWriter);
    writer.writeBytes<uint8_t>(instrWriter.get());
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
    case TYPE_IsolatedInstruction: {
        auto semantic = new IsolatedInstruction();
        semantic->setData(reader.readBytes<uint8_t>());
        return semantic;
    }
    case TYPE_LinkedInstruction: {
        auto semantic = new LinkedInstruction(instruction);
        semantic->setData(reader.readBytes<uint8_t>());
        semantic->setLink(LinkSerializer(op).deserialize(reader));
#ifdef ARCH_X86_64
        semantic->setIndex(reader.read<uint8_t>());
#endif
        return semantic;
    }
    case TYPE_ReturnInstruction: {
        auto semantic = new ReturnInstruction();
        semantic->setData(reader.readBytes<uint8_t>());
        return semantic;
    }
    case TYPE_IndirectJumpInstruction: {
        auto mnemonic = reader.readString();
        auto reg = reader.read<uint8_t>();
        auto semantic = new IndirectJumpInstruction(
            static_cast<Register>(reg), mnemonic);
        semantic->setData(reader.readBytes<uint8_t>());

        auto tableCount = reader.read<uint32_t>();
        for(uint32_t i = 0; i < tableCount; i ++) {
            semantic->addJumpTable(op.lookupAs<JumpTable>(reader.readID()));
        }
        return semantic;
    }
    case TYPE_IndirectCallInstruction: {
        auto reg = reader.read<uint32_t>();
        auto semantic = new IndirectCallInstruction(
            static_cast<Register>(reg));
        semantic->setData(reader.readBytes<uint8_t>());
        return semantic;
    }
    case TYPE_StackFrameInstruction:
        throw "StackFrameInstruction?";
    case TYPE_LiteralInstruction:
        throw "LiteralInstruction?";
    case TYPE_LinkedLiteralInstruction: {
        return defaultDeserialize(instruction, address, reader);
    }
    case TYPE_ControlFlowInstruction: {
#ifdef ARCH_X86_64
        auto id = reader.read<uint32_t>();  // NOT a chunk ID
        auto source = op.lookupAs<Instruction>(reader.readID());
        auto opcode = reader.readBytes<uint8_t>();
        auto mnemonic = reader.readString();
        auto dispSize = reader.read<uint8_t>();
        auto semantic = new ControlFlowInstruction(id, source, opcode,
            mnemonic, dispSize);
#elif defined(ARCH_AARCH64)
        auto semantic = new ControlFlowInstruction(instruction);
#elif defined(ARCH_RISCV)
        // XXX: maybe?
        auto semantic = new ControlFlowInstruction(instruction);
#endif
        bool returns = reader.read<bool>();
        if(!returns) semantic->setNonreturn();

        semantic->setLink(LinkSerializer(op).deserialize(reader));
        return semantic;
    }
#ifdef ARCH_X86_64
    case TYPE_DataLinkedControlFlowInstruction: {
        auto semantic = new DataLinkedControlFlowInstruction(instruction);
        semantic->setData(reader.readBytes<uint8_t>());
        semantic->setLink(LinkSerializer(op).deserialize(reader));
#ifdef ARCH_X86_64
        semantic->setIndex(reader.read<uint8_t>());
#endif

        //bool isRelative = reader.read<bool>(); // not needed, setLink sets isRelative

        return semantic;
    }
#endif
    default:
        break;
    }

    LOG(11, "Unknown instruction type " << std::dec << static_cast<int>(type)
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
        auto ins = new IsolatedInstruction();
        ins->setData(bytes);
        return ins;
    }
#else
    RawByteStorage storage(bytes);
    return new RawInstruction(std::move(storage));
#endif
}

void LinkSerializer::serialize(Link *link, ArchiveStreamWriter &writer) {
    if(dynamic_cast<AbsoluteNormalLink *>(link)) {
        writer.write<uint8_t>(TYPE_AbsoluteNormalLink);
        writer.write<uint8_t>(link->getScope());
        writer.writeID(op.assign(&*link->getTarget()));
    }
    else if(dynamic_cast<NormalLink *>(link)) {
        writer.write<uint8_t>(TYPE_NormalLink);
        writer.write<uint8_t>(link->getScope());
        writer.writeID(op.assign(&*link->getTarget()));
    }
    else if(dynamic_cast<OffsetLink *>(link)) {
        writer.write<uint8_t>(TYPE_OffsetLink);
        writer.write<uint8_t>(link->getScope());
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
        writer.writeID(op.assign(&*link->getTarget()));
    }
    else if(auto v = dynamic_cast<EgalitoLoaderLink *>(link)) {
        writer.write<uint8_t>(TYPE_EgalitoLoaderLink);
        writer.writeString(v->getTargetName());
    }
    else if(dynamic_cast<SymbolOnlyLink *>(link)) {
        writer.write<uint8_t>(TYPE_SymbolOnlyLink);
        LOG(0, "SymbolOnlyLink serialization not supported");
    }
    else if(dynamic_cast<MarkerLink *>(link)) {
        writer.write<uint8_t>(TYPE_MarkerLink);
        LOG(0, "MarkerLink serialization not supported");
    }
    else if(dynamic_cast<AbsoluteDataLink *>(link)) {
        writer.write<uint8_t>(TYPE_AbsoluteDataLink);
        auto section = link->getTarget();
        writer.writeID(op.assign(&*section));
        writer.write(link->getTargetAddress() - section->getAddress());
    }
    else if(dynamic_cast<DataOffsetLink *>(link)) {
        writer.write<uint8_t>(TYPE_DataOffsetLink);
        writer.write<uint8_t>(link->getScope());
        auto section = link->getTarget();
        writer.writeID(op.assign(&*section));
        writer.write(link->getTargetAddress() - section->getAddress());
    }
    else if(auto v = dynamic_cast<TLSDataOffsetLink *>(link)) {
        writer.write<uint8_t>(TYPE_TLSDataOffsetLink);
        writer.writeID(op.assign(v->getTLSRegion()));
        writer.write(v->getRawTarget());
        writer.write<bool>(v->getSymbol() != nullptr);
        if(v->getSymbol()) {
            writer.writeString(v->getSymbol()->getName());  // should be WEAK
        }
    }
    else if(dynamic_cast<UnresolvedLink *>(link)) {
        writer.write<uint8_t>(TYPE_UnresolvedLink);
        writer.write(link->getTargetAddress());
    }
    else if(auto v = dynamic_cast<ImmAndDispLink *>(link)) {
        writer.write<uint8_t>(TYPE_ImmAndDispLink);
        writer.write<uint8_t>(v->getImmLink()->getScope());
        writer.writeID(op.assign(&*v->getImmLink()->getTarget()));
        serialize(v->getDispLink(), writer);
    }
    else {
        writer.write<uint8_t>(TYPE_UNKNOWN_LINK);
    }
}

Link *LinkSerializer::deserialize(ArchiveStreamReader &reader) {
    auto type = reader.read<uint8_t>();
    if(!reader.stillGood()) return nullptr;

    switch(type) {
    case TYPE_AbsoluteNormalLink: {
        auto scope = static_cast<Link::LinkScope>(reader.read<uint8_t>());
        return new AbsoluteNormalLink(deserializeLinkTarget(reader), scope);
    }
    case TYPE_NormalLink: {
        auto scope = static_cast<Link::LinkScope>(reader.read<uint8_t>());
        return new NormalLink(deserializeLinkTarget(reader), scope);
    }
    case TYPE_OffsetLink: {
        auto scope = static_cast<Link::LinkScope>(reader.read<uint8_t>());
        auto target = deserializeLinkTarget(reader);
        auto offset = reader.read<address_t>();
        return new OffsetLink(target, offset, scope);
    }
    case TYPE_PLTLink:
        return new PLTLink(0x0,
            dynamic_cast<PLTTrampoline *>(deserializeLinkTarget(reader)));
    case TYPE_JumpTableLink:
        return new JumpTableLink(
            dynamic_cast<JumpTable *>(deserializeLinkTarget(reader)));
    case TYPE_EgalitoLoaderLink:
        return new EgalitoLoaderLink(reader.readString());
    case TYPE_SymbolOnlyLink:
        return new UnresolvedLink(0);  // unsupported
    case TYPE_MarkerLink:
        return new UnresolvedLink(0);  // unsupported
    case TYPE_AbsoluteDataLink: {
        auto section = dynamic_cast<DataSection *>(deserializeLinkTarget(reader));
        auto offset = reader.read<address_t>();
        return new AbsoluteDataLink(section, offset);
    }
    case TYPE_DataOffsetLink: {
        auto scope = static_cast<Link::LinkScope>(reader.read<uint8_t>());
        auto section = dynamic_cast<DataSection *>(deserializeLinkTarget(reader));
        auto offset = reader.read<address_t>();
        return new DataOffsetLink(section, offset, scope);
    }
    case TYPE_TLSDataOffsetLink: {
        auto tls = dynamic_cast<TLSDataRegion *>(deserializeLinkTarget(reader));
        auto rawTarget = reader.read<address_t>();
        auto hasSymbol = reader.read<bool>();
        Symbol *symbol = nullptr;
        if(hasSymbol) {
            auto symbolName = reader.readString();
            symbol = new Symbol(0x0, 0, symbolName.c_str(),
                Symbol::TYPE_UNKNOWN, Symbol::BIND_WEAK, 0, 0);
        }
        return new TLSDataOffsetLink(tls, symbol, rawTarget);
    }
    case TYPE_UnresolvedLink:
        return new UnresolvedLink(reader.read<address_t>());
    case TYPE_ImmAndDispLink: {
        auto immScope = static_cast<Link::LinkScope>(reader.read<uint8_t>());
        auto immLink = new NormalLink(op.lookup(reader.readID()), immScope);
        auto dispLink = deserialize(reader);
        return new ImmAndDispLink(immLink, dispLink);
    }
    case TYPE_UNKNOWN_LINK:
    default:
        return new UnresolvedLink(0);
    }
}

Chunk *LinkSerializer::deserializeLinkTarget(ArchiveStreamReader &reader) {
    auto id = reader.readID();  // can be NoneID
    Chunk *target = op.lookup(id);  // can be nullptr
    if(target && !target->getPosition()) {
        try {
            target->setPosition(new AbsolutePosition(-1));
        }
        catch(const char *) {
            // can't set position for this type
        }
    }
    return target;
}
