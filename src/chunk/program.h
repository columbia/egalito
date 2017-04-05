#ifndef EGALITO_CHUNK_PROGRAM_H
#define EGALITO_CHUNK_PROGRAM_H

#include "chunk.h"

class Program : public ChunkImpl {
public:
    virtual void accept(ChunkVisitor *visitor);
};

#endif
