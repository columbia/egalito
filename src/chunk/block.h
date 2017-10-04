#ifndef EGALITO_CHUNK_BLOCK_H
#define EGALITO_CHUNK_BLOCK_H

#include "chunk.h"
#include "chunklist.h"
#include "instr/instr.h"
#include "archive/chunktypes.h"

class Block : public ChunkSerializerImpl<TYPE_Block,
    CompositeChunkImpl<Instruction>> {
public:
    virtual std::string getName() const;

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
