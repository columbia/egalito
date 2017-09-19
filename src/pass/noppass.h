#ifndef EGALITO_PASS_NOP_PASS_H
#define EGALITO_PASS_NOP_PASS_H

#include "chunkpass.h"

/** Adds nop instruction before every instruction. */
class NopPass : public ChunkPass {
public:
    virtual void visit(Block *block);
};

#endif
