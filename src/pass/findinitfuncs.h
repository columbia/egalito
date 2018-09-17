#ifndef EGALITO_PASS_FIND_INIT_FUNCS_H
#define EGALITO_PASS_FIND_INIT_FUNCS_H

#include "chunkpass.h"

class FindInitFuncs : public ChunkPass {
public:
    virtual void visit(Module *module);
};

#endif
