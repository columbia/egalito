#ifndef EGALITO_PASS_JUMP_TABLE_PASS_H
#define EGALITO_PASS_JUMP_TABLE_PASS_H

#include "chunkpass.h"

class JumpTablePass : public ChunkPass {
public:
    virtual void visit(Module *module);
};

#endif
