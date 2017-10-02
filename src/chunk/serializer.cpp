#include <cassert>
#include <functional>
#include "serializer.h"
#include "chunk.h"
#include "chunklist.h"
#include "concrete.h"  // for instantiation
#include "archive/stream.h"

FlatChunk::IDType ChunkSerializerOperations::serialize(Chunk *chunk) {
    FlatChunk *flat = archive->getFlatList().newFlatChunk(
        chunk->getFlatType());
    BufferedStreamWriter writer(flat);

    chunk->serialize(*this, writer);
    return flat->getID();
}

void ChunkSerializerOperations::serialize(Chunk *chunk,
    FlatChunk::IDType id) {

    FlatChunk *flat = archive->getFlatList().newFlatChunk(
        chunk->getFlatType(), id);
    BufferedStreamWriter writer(flat);

    chunk->serialize(*this, writer);
}

bool ChunkSerializerOperations::deserialize(FlatChunk *flat) {
    InMemoryStreamReader reader(flat);
    flat->getInstance<Chunk>()->deserialize(*this, reader);
    return reader.stillGood();
}

void ChunkSerializerOperations::serializeChildren(Chunk *chunk,
    ArchiveStreamWriter &writer) {

    writer.write(static_cast<uint32_t>(chunk->getChildren()
        ->genericGetSize()));

    std::vector<FlatChunk::IDType> idList;
    for(auto child : chunk->getChildren()->genericIterable()) {
        idList.push_back(assign(child));
        writer.write(idList.back());
    }

    writer.flush();

    size_t i = 0;
    for(auto child : chunk->getChildren()->genericIterable()) {
        this->serialize(child, idList[i ++]);
    }
}

void ChunkSerializerOperations::deserializeChildren(Chunk *chunk,
    ArchiveStreamReader &reader) {

    uint32_t count;
    reader.read(count);

    std::vector<FlatChunk::IDType> idList;
    for(uint32_t i = 0; i < count; i ++) {
        uint32_t id;
        reader.read(id);
        idList.push_back(id);
        chunk->getChildren()->genericAdd(lookup(id));
    }

    for(auto id : idList) {
        this->deserialize(lookupFlat(id));
    }
}

FlatChunk::IDType ChunkSerializerOperations::assign(Chunk *chunk) {
    return archive->getFlatList().getNextID();
}

Chunk *ChunkSerializerOperations::instantiate(FlatChunk *flat) {
    std::function<Chunk *()> constructor[] = {
        [] () -> Chunk* { return nullptr; },              // TYPE_UNKNOWN
        [] () -> Chunk* { return new Program(nullptr); },        // TYPE_Program
        [] () -> Chunk* { return new Module(); },         // TYPE_Module
#if 0
        [] () -> Chunk* { return new FunctionList(); },   // TYPE_FunctionList
        [] () -> Chunk* { return new PLTList(); },        // TYPE_PLTList
        [] () -> Chunk* { return new JumpTableList(); },  // TYPE_JumpTableList
        [] () -> Chunk* { return new DataRegionList(); }, // TYPE_DataRegionList
        [] () -> Chunk* { return new FuzzyFunction(); },       // TYPE_Function
        [] () -> Chunk* { return new Block(); },          // TYPE_Block
        [] () -> Chunk* { return new Instruction(); },    // TYPE_Instruction
        [] () -> Chunk* { return new PLTTrampoline(); },  // TYPE_PLTTrampoline
        [] () -> Chunk* { return new JumpTable(); },      // TYPE_JumpTable
        [] () -> Chunk* { return new JumpTableEntry(); }, // TYPE_JumpTableEntry
        [] () -> Chunk* { return new DataRegion(); },     // TYPE_DataRegion
        [] () -> Chunk* { return new DataSection(); },    // TYPE_DataSection
        [] () -> Chunk* { return new DataVariable(); },   // TYPE_DataVariable
        [] () -> Chunk* { return new MarkerList(); },     // TYPE_MarkerList
        [] () -> Chunk* { return new Marker(); },         // TYPE_Marker
#else
        [] () -> Chunk* { return new FunctionList(); },   // TYPE_FunctionList
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return new FuzzyFunction(); },       // TYPE_Function
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
        [] () -> Chunk* { return nullptr; },
#endif
    };

    assert(flat != nullptr);
    const auto &type = flat->getType();
    assert(type < sizeof(constructor)/sizeof(*constructor));

    return (constructor[type])();
}

Chunk *ChunkSerializerOperations::lookup(FlatChunk::IDType id) {
    return archive->getFlatList().get(id)->getInstance<Chunk>();
}

FlatChunk *ChunkSerializerOperations::lookupFlat(FlatChunk::IDType id) {
    return archive->getFlatList().get(id);
}
