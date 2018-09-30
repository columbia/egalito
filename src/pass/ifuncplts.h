#ifndef EGALITO_PASS_IFUNCPLTS_H
#define EGALITO_PASS_IFUNCPLTS_H

#include "chunkpass.h"

/** Adds nop instruction before every instruction. */
class IFuncPLTs : public ChunkPass {
public:
    virtual void visit(Module *module);
    virtual void visit(PLTList *pltList);
    virtual void visit(PLTTrampoline *trampoline);
private:
    void freeChildren(Chunk *chunk, int level);
};

#endif
