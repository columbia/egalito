#ifndef EGALITO_CHUNK_SERIALIZER_H
#define EGALITO_CHUNK_SERIALIZER_H

#include <map>
#include "archive/archive.h"
#include "archive/flatchunk.h"
#include "archive/stream.h"

class Chunk;

/** Operations available to a Chunk's serialize/deserialize functions.
*/
class ChunkSerializerOperations {
private:
    EgalitoArchive *archive;
    std::map<Chunk *, FlatChunk::IDType> assignment;
public:
    ChunkSerializerOperations(EgalitoArchive *archive) : archive(archive) {}

    int getVersion() const { return archive->getVersion(); }

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

    template <typename Type>
    Type *lookupAs(FlatChunk::IDType id)
        { return archive->getFlatList().get(id)->getInstance<Type>(); }
};

/** Highest-level archive serialization/deserialization.
*/
class ChunkSerializer {
public:
    /** Here chunk is the root of the tree to serialize. */
    void serialize(Chunk *chunk, std::string filename);

    /** Returns the root of the deserialized tree. */
    Chunk *deserialize(std::string filename);
};

#endif
