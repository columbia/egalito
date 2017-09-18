#include <cstring>
#include <cstdint>
#include <cassert>
#include <fstream>
#include "serialize.h"
#include "chunk.h"
#include "concrete.h"
#include "visitor.h"
#include "archive/generic.h"
#include "archive/reader.h"
#include "archive/writer.h"
#include "archive/flatchunk.h"
#include "log/log.h"

class SerializeImpl : public ChunkListener {
private:
    EgalitoArchiveWriter &archive;
public:
    SerializeImpl(EgalitoArchiveWriter &archive) : archive(archive) {}
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    //virtual void visit(FunctionList *functionList);
    //virtual void visit(PLTList *pltList);
    //virtual void visit(JumpTableList *jumpTableList);
    //virtual void visit(DataRegionList *dataRegionList);
    //virtual void visit(Function *function);
    //virtual void visit(Block *block);
    //virtual void visit(Instruction *instruction);
    //virtual void visit(PLTTrampoline *instruction);
    //virtual void visit(JumpTable *jumpTable);
    //virtual void visit(JumpTableEntry *jumpTableEntry);
    //virtual void visit(DataRegion *dataRegion);
};

void SerializeImpl::visit(Program *program) {
    archive.getFlatList().newFlatChunk(EgalitoArchive::TYPE_Program);
    archive.getFlatList().append32(program->getChildren()
        ->getIterable()->getCount());

    for(auto module : CIter::children(program)) {
        module->accept(this);
    }
}

void SerializeImpl::visit(Module *module) {
    archive.getFlatList().newFlatChunk(EgalitoArchive::TYPE_Module);
}

class DeserializeImpl {
private:
    EgalitoArchiveReader &archive;
    EgalitoArchive::EgalitoChunkType debugType;
public:
    DeserializeImpl(EgalitoArchiveReader &archive) : archive(archive) {}
    Chunk *parse(const FlatChunk &flat);
private:
    typedef Chunk *(DeserializeImpl::*ChunkBuilder)();
    Chunk *makeProgram();
    Chunk *notYetImplemented();
};

Chunk *DeserializeImpl::parse(const FlatChunk &flat) {
    static const ChunkBuilder decoder[] = {
        &DeserializeImpl::makeProgram,          // TYPE_Program
        &DeserializeImpl::notYetImplemented,    // TYPE_Module
        &DeserializeImpl::notYetImplemented,    // TYPE_FunctionList
        &DeserializeImpl::notYetImplemented,    // TYPE_PLTList
        &DeserializeImpl::notYetImplemented,    // TYPE_JumpTableList
        &DeserializeImpl::notYetImplemented,    // TYPE_DataRegionList
        &DeserializeImpl::notYetImplemented,    // TYPE_Function
        &DeserializeImpl::notYetImplemented,    // TYPE_Block
        &DeserializeImpl::notYetImplemented,    // TYPE_Instruction
        &DeserializeImpl::notYetImplemented,    // TYPE_PLTTrampoline
        &DeserializeImpl::notYetImplemented,    // TYPE_JumpTable
        &DeserializeImpl::notYetImplemented,    // TYPE_JumpTableEntry
        &DeserializeImpl::notYetImplemented,    // TYPE_DataRegion
        &DeserializeImpl::notYetImplemented,    // TYPE_DataSection
        &DeserializeImpl::notYetImplemented,    // TYPE_DataVariable
        &DeserializeImpl::notYetImplemented,    // TYPE_MarkerList
        &DeserializeImpl::notYetImplemented,    // TYPE_Marker
    };

    const auto &type = flat.getType();
    assert(type < sizeof(decoder)/sizeof(*decoder));

    this->debugType = static_cast<EgalitoArchive::EgalitoChunkType>(flat.getType());
    Chunk *result = (this->*decoder[type])();
    return result;
}

Chunk *DeserializeImpl::makeProgram() {
    //return new Program(nullptr);
    return nullptr;
}

Chunk *DeserializeImpl::notYetImplemented() {
    LOG(1, "WARNING: not yet implemented: deserialize archive chunk type "
        << debugType);
    return nullptr;
}

void ChunkSerializer::serialize(Chunk *chunk, std::string filename) {
    EgalitoArchiveWriter archive;
    SerializeImpl serializer(archive);
    chunk->accept(&serializer);

    archive.writeTo(filename);
}

Chunk *ChunkSerializer::deserialize(std::string filename) {
    EgalitoArchiveReader archive;
    DeserializeImpl deserializer(archive);

    std::vector<Chunk *> chunkList;

    archive.readFlatList(filename);
    for(const auto &flat : archive.getFlatList()) {
        Chunk *chunk = deserializer.parse(flat);
        chunkList.push_back(chunk);
    }

    return chunkList.size() ? chunkList[0] : nullptr;
}
