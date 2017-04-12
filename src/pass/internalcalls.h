#ifndef EGALITO_INTERNAL_CALLS_H
#define EGALITO_INTERNAL_CALLS_H

#include "chunkpass.h"

class InternalCalls : public ChunkPass {
private:
    FunctionList *functionList;
public:
    InternalCalls() : functionList(nullptr) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
