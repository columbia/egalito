#ifndef EGALITO_CHUNK_RESOLVE_H
#define EGALITO_CHUNK_RESOLVE_H

#include "chunkpass.h"

class ResolveCalls : public ChunkPass {
private:
    SpatialChunkList<Function> *functionList;
public:
    ResolveCalls() : functionList(nullptr) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
