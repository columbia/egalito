#ifndef EGALITO_PASS_HANDLE_RELOCS_H
#define EGALITO_PASS_HANDLE_RELOCS_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

class HandleRelocsPass : public ChunkPass {
private:
    ElfMap *elf;
    RelocList *relocList;
    Module *module;
public:
    HandleRelocsPass(ElfMap *elf, RelocList *relocList)
        : elf(elf), relocList(relocList), module(nullptr) {}
    virtual void visit(Module *module);
private:
    void handleRelocation(Reloc *r, Instruction *instruction);
    void handleRelocation(Reloc *r, Instruction *instruction,
        Symbol *symbol);
};

#endif
