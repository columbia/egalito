#ifndef EGALITO_CHUNK_SERIALIZER_H
#define EGALITO_CHUNK_SERIALIZER_H

#include "archive/archive.h"
#include "archive/flatchunk.h"
#include "archive/stream.h"

class Chunk;

class ChunkSerializerOperations {
private:
    EgalitoArchive *archive;
public:
    ChunkSerializerOperations(EgalitoArchive *archive) : archive(archive) {}

    virtual FlatChunk::IDType serialize(Chunk *chunk);
    virtual void serialize(Chunk *chunk, FlatChunk::IDType id);
    virtual bool deserialize(FlatChunk *flat);

    virtual void serializeChildren(Chunk *chunk,
        ArchiveStreamWriter &writer);
    virtual void deserializeChildren(Chunk *chunk,
        ArchiveStreamReader &reader);

    FlatChunk::IDType assign(Chunk *chunk);
    Chunk *instantiate(FlatChunk *flat);

    Chunk *lookup(FlatChunk::IDType id);
    FlatChunk *lookupFlat(FlatChunk::IDType id);
};

class ChunkSerializer2 {
public:
    virtual FlatChunk::FlatType getFlatType() const = 0;
    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer) = 0;
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader) = 0;
};

#endif
