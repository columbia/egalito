#ifndef EGALITO_PASS_SPLIT_FUCTION_H
#define EGALITO_PASS_SPLIT_FUCTION_H

#include "chunkpass.h"

class Function;

class SplitFunction : public ChunkPass {
public:
    SplitFunction() {}
    virtual void visit(Function *function);
};

#endif
