#ifndef EGALITO_PASS_COLLECT_GLOBALS_H
#define EGALITO_PASS_COLLECT_GLOBALS_H

#include "pass/chunkpass.h"

class CollectGlobalsPass : public ChunkPass {
public:
    virtual void visit(Module *module);
};

#endif
