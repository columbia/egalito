#ifndef EGALITO_PASS_FALLTHROUGH_H
#define EGALITO_PASS_FALLTHROUGH_H

#include "chunkpass.h"

class FallThroughFunctionPass : public ChunkPass {
public:
    FallThroughFunctionPass() {}
    virtual void visit(Function *function);
};

#endif
