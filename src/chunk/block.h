#ifndef EGALITO_CHUNK_BLOCK_H
#define EGALITO_CHUNK_BLOCK_H

#include "chunk.h"
#include "chunklist.h"
#include "instr/instr.h"

class Block : public CompositeChunkImpl<Instruction> {
public:
    virtual std::string getName() const;

    virtual void accept(ChunkVisitor *visitor);
};

#endif
