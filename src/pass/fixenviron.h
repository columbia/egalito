#ifndef EGALITO_PASS_FIX_ENVIRON_H
#define EGALITO_PASS_FIX_ENVIRON_H

#include "chunkpass.h"

class FixEnvironPass : public ChunkPass {
public:
    virtual void visit(Program *program);
};

#endif
