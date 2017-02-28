#ifndef EGALITO_PASS_INFERRED_PTRS_H
#define EGALITO_PASS_INFERRED_PTRS_H

#include "chunkpass.h"
#include "elf/elfmap.h"

class InferredPtrsPass : public ChunkPass {
private:
    ElfMap *elf;
    Module *module;
public:
    InferredPtrsPass(ElfMap *elf) : elf(elf) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
