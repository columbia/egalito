#ifndef EGALITO_PASS_INFER_LINKS_H
#define EGALITO_PASS_INFER_LINKS_H

#include "chunkpass.h"
#include "elf/elfmap.h"

class InferLinksPass : public ChunkPass {
private:
    ElfMap *elf;
    Module *module;
public:
    InferLinksPass(ElfMap *elf) : elf(elf), module(nullptr) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
