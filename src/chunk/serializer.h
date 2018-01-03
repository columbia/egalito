#ifndef EGALITO_CHUNK_SERIALIZER_H
#define EGALITO_CHUNK_SERIALIZER_H

#include <map>
#include "archive/archive.h"
#include "archive/operations.h"
#include "archive/flatchunk.h"
#include "archive/stream.h"

class Chunk;

/** Operations available to a Chunk's serialize/deserialize functions.
*/
class ChunkSerializerOperations : public ArchiveIDOperations<Chunk> {
private:
    EgalitoArchive *archive;
    bool localModuleOnly;
    std::vector<std::string> debugNames;
public:
    ChunkSerializerOperations(EgalitoArchive *archive, bool localModuleOnly)
        : ArchiveIDOperations(archive), localModuleOnly(localModuleOnly) {}

    virtual FlatChunk::IDType assign(Chunk *object);
    std::string getDebugName(FlatChunk::IDType id);

    FlatChunk::IDType serialize(Chunk *chunk);
    void serialize(Chunk *chunk, FlatChunk::IDType id);
    bool deserialize(FlatChunk *flat);

    void serializeChildren(Chunk *chunk,
        ArchiveStreamWriter &writer);
    void deserializeChildren(Chunk *chunk,
        ArchiveStreamReader &reader, bool addToChildList = true);
    void serializeChildrenIDsOnly(Chunk *chunk,
        ArchiveStreamWriter &writer, int level);
    void deserializeChildrenIDsOnly(Chunk *chunk,
        ArchiveStreamReader &reader, int level, bool addToChildList = true);

    bool isLocalModuleOnly() const { return localModuleOnly; }
};

/** Highest-level archive serialization/deserialization.
*/
class ChunkSerializer {
public:
    /** Here chunk is the root of the tree to serialize. */
    void serialize(Chunk *chunk, std::string filename);

    /** Returns the root of the deserialized tree. */
    Chunk *deserialize(std::string filename);
private:
    Chunk *instantiate(FlatChunk *flat);
};

#endif
