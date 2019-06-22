#ifndef EGALITO_PASS_INFER_LINKS_H
#define EGALITO_PASS_INFER_LINKS_H

#include "chunkpass.h"
#include "elf/elfmap.h"

class InferLinksPass : public ChunkPass {
private:
    Module *module;
public:
    InferLinksPass() : module(nullptr) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
