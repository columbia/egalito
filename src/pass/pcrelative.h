#ifndef EGALITO_PASS_PCRELATIVE_H
#define EGALITO_PASS_PCRELATIVE_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

// pick up any instruction that have PC-relative immediates
// function pointer should be resolved before running this pass
class PCRelativePass : public ChunkPass {
private:
    ElfMap *elf;
    RelocList *relocList;
public:
    PCRelativePass(ElfMap *elf, RelocList *relocList) : elf(elf), relocList(relocList) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction) {}
private:
    virtual void handlePCRelative(Reloc *r, Module *module);
};

#endif
