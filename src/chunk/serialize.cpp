#include <cstring>
#include <cstdint>
#include <cassert>
#include <sstream>
#include "serialize.h"
#include "chunk.h"
#include "concrete.h"
#include "visitor.h"
#include "archive/generic.h"
#include "archive/reader.h"
#include "archive/writer.h"
#include "archive/flatchunk.h"
#include "archive/stream.h"
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

    std::ostringstream stream;
    ArchiveStreamWriter writer(stream);

    writer.writeAnyLength(module->getName());

    archive.getFlatList().appendData(stream.str());
}

class DeserializeImpl {
private:
    EgalitoArchiveReader &archive;
public:
    DeserializeImpl(EgalitoArchiveReader &archive) : archive(archive) {}
    Chunk *parse(const FlatChunk &flat);
private:
    typedef Chunk *(DeserializeImpl::*ChunkBuilder)(const FlatChunk &flat);
    Chunk *makeProgram(const FlatChunk &flat);
    Chunk *makeModule(const FlatChunk &flat);
    Chunk *notYetImplemented(const FlatChunk &flat);
};

Chunk *DeserializeImpl::parse(const FlatChunk &flat) {
    static const ChunkBuilder decoder[] = {
        &DeserializeImpl::makeProgram,          // TYPE_Program
        &DeserializeImpl::makeModule,           // TYPE_Module
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

    Chunk *result = (this->*decoder[type])(flat);
    return result;
}

Chunk *DeserializeImpl::makeProgram(const FlatChunk &flat) {
    return new Program(nullptr);
}

Chunk *DeserializeImpl::makeModule(const FlatChunk &flat) {
    std::istringstream stream(flat.getData());
    ArchiveStreamReader reader(stream);

    std::string name;
    reader.readAnyLength(name);

    LOG(1, "trying to parse Module [" << name << "]");

    return nullptr;
}

Chunk *DeserializeImpl::notYetImplemented(const FlatChunk &flat) {
    LOG(1, "WARNING: not yet implemented: deserialize archive chunk type "
        << flat.getType());
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
