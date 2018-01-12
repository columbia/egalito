#ifndef EGALITO_PASS_MAKECACHE_H
#define EGALITO_PASS_MAKECACHE_H

#include "pass/chunkpass.h"

class MakeCachePass : public ChunkPass {
public:
    virtual void visit(Function *function);
    virtual void visit(PLTTrampoline *trampoline);
};

#endif
