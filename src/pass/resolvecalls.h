#ifndef EGALITO_CHUNK_RESOLVE_H
#define EGALITO_CHUNK_RESOLVE_H

#include "chunkpass.h"

class ResolveCalls : public ChunkPass {
private:
    SpatialChunkList<Function> functionList;
public:
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
private:
    Chunk *find(Chunk *root, address_t targetAddress);
    Chunk *findHelper(Chunk *root, address_t targetAddress);
};

#endif
