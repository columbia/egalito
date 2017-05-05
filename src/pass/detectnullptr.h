#ifndef EGALITO_PASS_DETECT_NULL_PTR_H
#define EGALITO_PASS_DETECT_NULL_PTR_H

#include "chunkpass.h"

class Symbol;

class DetectNullPtrPass : public ChunkPass {
private:
    Symbol *failFunc;
public:
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
