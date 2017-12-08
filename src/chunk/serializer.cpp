#include <cassert>
#include <functional>
#include "serializer.h"
#include "chunk.h"
#include "chunklist.h"
#include "concrete.h"  // for instantiation
#include "archive/stream.h"
#include "archive/reader.h"
#include "archive/writer.h"
#include "util/timing.h"
#include "log/log.h"

FlatChunk::IDType ChunkSerializerOperations::assign(Chunk *object) {
    auto id = ArchiveIDOperations<Chunk>::assign(object);
    if(id != FlatChunk::NoneID) {
        if(debugNames.size() <= id) debugNames.resize(id + 1);
        debugNames[id] = object->getName();
    }
    return id;
}

std::string ChunkSerializerOperations::getDebugName(FlatChunk::IDType id) {
    return (id < debugNames.size() ? debugNames[id] : "???");
}

FlatChunk::IDType ChunkSerializerOperations::serialize(Chunk *chunk) {
    FlatChunk *flat = getArchive()->getFlatList().newFlatChunk(
        chunk->getFlatType());
    BufferedStreamWriter writer(flat);

    chunk->serialize(*this, writer);
    return flat->getID();
}

void ChunkSerializerOperations::serialize(Chunk *chunk,
    FlatChunk::IDType id) {

    FlatChunk *flat = getArchive()->getFlatList().newFlatChunk(
        chunk->getFlatType(), id);
    BufferedStreamWriter writer(flat);

    chunk->serialize(*this, writer);
}

bool ChunkSerializerOperations::deserialize(FlatChunk *flat) {
    InMemoryStreamReader reader(flat);
    if(!flat->getInstance<Chunk>()) {
        LOG(1, "WARNING: did not instantiate Chunk for flat " << flat->getID());
        return false;
    }

    flat->getInstance<Chunk>()->deserialize(*this, reader);
    return reader.stillGood();
}

void ChunkSerializerOperations::serializeChildren(Chunk *chunk,
    ArchiveStreamWriter &writer) {

    uint32_t count = chunk->getChildren()->genericGetSize();
    writer.write(count);

    std::vector<FlatChunk::IDType> idList;
    for(auto child : chunk->getChildren()->genericIterable()) {
        idList.push_back(assign(child));
        writer.write(idList.back());
    }

    writer.flush();

    size_t i = 0;
    for(auto child : chunk->getChildren()->genericIterable()) {
        //LOG(1, "    serialize child with id " << idList[i]);
        this->serialize(child, idList[i ++]);
    }
}

void ChunkSerializerOperations::deserializeChildren(Chunk *chunk,
    ArchiveStreamReader &reader, bool addToChildList) {

    auto count = reader.read<uint32_t>();

    std::vector<FlatChunk::IDType> idList;
    for(uint32_t i = 0; i < count; i ++) {
        auto id = reader.readID();
        idList.push_back(id);
        if(addToChildList) {
            Chunk *child = lookup(id);
            chunk->getChildren()->genericAdd(child);
            child->setParent(chunk);
        }
    }

    // we deserialize all Chunks, not in order
    /*for(auto id : idList) {
        this->deserialize(lookupFlat(id));
    }*/
}

void ChunkSerializerOperations::serializeChildrenIDsOnly(Chunk *chunk,
    ArchiveStreamWriter &writer, int level) {

    if(level <= 0) return;
    assert(chunk->getChildren());

    uint32_t count = chunk->getChildren()->genericGetSize();
    writer.write(count);

    for(auto child : chunk->getChildren()->genericIterable()) {
        auto id = assign(child);
        auto type = child->getFlatType();
        getArchive()->getFlatList().newFlatChunk(type, id);  // unused ret val

        writer.writeID(id);
    }

    if(level > 1) {
        for(auto child : chunk->getChildren()->genericIterable()) {
            serializeChildrenIDsOnly(child, writer, level - 1);
        }
    }
}

void ChunkSerializerOperations::deserializeChildrenIDsOnly(Chunk *chunk,
    ArchiveStreamReader &reader, int level, bool addToChildList) {

    if(level <= 0) return;

    auto count = reader.read<uint32_t>();

    std::vector<FlatChunk::IDType> idList;
    for(uint32_t i = 0; i < count; i ++) {
        auto id = reader.readID();
        idList.push_back(id);
        if(addToChildList) {
            Chunk *child = lookup(id);
            chunk->getChildren()->genericAdd(child);
            child->setParent(chunk);
        }
    }

    if(level > 1) {
        for(auto id : idList) {
            auto child = lookup(id);
            deserializeChildrenIDsOnly(child, reader, level - 1);
        }
    }
}

Chunk *ChunkSerializer::instantiate(FlatChunk *flat) {
    std::function<Chunk *()> constructor[] = {
        [] () -> Chunk* { return nullptr; },              // TYPE_UNKNOWN
        [] () -> Chunk* { return new Program(); },        // TYPE_Program
        [] () -> Chunk* { return new Module(); },         // TYPE_Module
        [] () -> Chunk* { return new FunctionList(); },   // TYPE_FunctionList
        [] () -> Chunk* { return new PLTList(); },        // TYPE_PLTList
        [] () -> Chunk* { return new JumpTableList(); },  // TYPE_JumpTableList
        [] () -> Chunk* { return new DataRegionList(); }, // TYPE_DataRegionList
        [] () -> Chunk* { return new ExternalSymbolList(); }, // TYPE_ExternalSymbolList
        [] () -> Chunk* { return new LibraryList(); },    // TYPE_LibraryList
        [] () -> Chunk* { return new Function(); },       // TYPE_Function
        [] () -> Chunk* { return new Block(); },          // TYPE_Block
        [] () -> Chunk* { return new Instruction(); },    // TYPE_Instruction
        [] () -> Chunk* { return new PLTTrampoline(); },  // TYPE_PLTTrampoline
        [] () -> Chunk* { return new JumpTable(); },      // TYPE_JumpTable
        [] () -> Chunk* { return new JumpTableEntry(); }, // TYPE_JumpTableEntry
        [] () -> Chunk* { return new DataRegion(); },     // TYPE_DataRegion
        [] () -> Chunk* { return new DataSection(); },    // TYPE_DataSection
        [] () -> Chunk* { return new DataVariable(); },   // TYPE_DataVariable
        [] () -> Chunk* { return nullptr; },    // TYPE_MarkerList
        [] () -> Chunk* { return nullptr; },    // TYPE_Marker
        [] () -> Chunk* { return new ExternalSymbol(); }, // TYPE_ExternalSymbol
        [] () -> Chunk* { return new Library(); },        // TYPE_Library
    };

    assert(flat != nullptr);
    const auto &type = flat->getType();
    assert(type < sizeof(constructor)/sizeof(*constructor));

    return (constructor[type])();
}

void ChunkSerializer::serialize(Chunk *chunk, std::string filename) {
    EgalitoArchive *archive = new EgalitoArchive();
    ChunkSerializerOperations op(archive);

    op.serialize(chunk);

    LOG(1, "done with root serialize call");

    // for sanity, make sure we serialized every Chunk that is referred to
    bool errors = false;
    FlatChunk::IDType id = 0;
    for(auto flat : archive->getFlatList()) {
        if(!flat) {
            LOG(1, "ERROR: Chunk \"" << op.getDebugName(id) << "\" at index "
                << std::dec << id << " was not serialized!");
            errors = true;
        }
        else {
            LOG(1, "serialize chunk id " << std::dec << id
                << " i.e. " << op.getDebugName(id));
        }
        id ++;
    }

    if(errors) {
        LOG(1, "Errors encountered during serialization, aborting");
    }
    else {
        EgalitoArchiveWriter(archive).write(filename);

        LOG(1, "done with writing");
    }

    delete archive;
}

Chunk *ChunkSerializer::deserialize(std::string filename) {
    EgalitoArchive *archive = EgalitoArchiveReader().read(filename);
    ChunkSerializerOperations op(archive);

    // First instantiate objects, with the correct type, so that memory
    // addresses are fixed (and pointers can be set during deserialization).
    for(auto flat : archive->getFlatList()) {
        flat->setInstance(instantiate(flat));
    }

    {
        EgalitoTiming ttt("total for all deserialize() calls");
        // Deserialize in reverse order so that tree leaves will be fully
        // initialized before their parents are constructed.
        for(auto it = archive->getFlatList().rbegin();
            it != archive->getFlatList().rend(); it ++) {

            op.deserialize(*it);
        }
    }

    // We assume node 0 is the root.
    auto root = op.lookup(0);
    delete archive;
    return root;
}
