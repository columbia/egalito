#ifndef EGALITO_PASS_CLEAR_PLTS_H
#define EGALITO_PASS_CLEAR_PLTS_H

#include "chunkpass.h"

class ClearPLTs : public ChunkPass {
public:
    virtual void visit(Module *module);
    virtual void visit(PLTTrampoline *plt);
private:
    void freeChildren(Chunk *chunk, int level);
};

#endif
