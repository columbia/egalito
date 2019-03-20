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
    bool resolveWeak;
public:
    HandleRelocsPass(ElfMap *elf, RelocList *relocList, bool resolveWeak)
        : elf(elf), relocList(relocList), module(nullptr),
        resolveWeak(resolveWeak) {}
    virtual void visit(Module *module);
private:
    void handleRelocation(Reloc *r, Instruction *instruction);
    void handleRelocation(Reloc *r, Instruction *instruction,
        Symbol *symbol);
};

class HandleRelocsStrong : public HandleRelocsPass {
public:
    HandleRelocsStrong(ElfMap *elf, RelocList *relocList) :
        HandleRelocsPass(elf, relocList, false) {}
};

class HandleRelocsWeak : public HandleRelocsPass {
public:
    HandleRelocsWeak(ElfMap *elf, RelocList *relocList) :
        HandleRelocsPass(elf, relocList, true) {}
};

#endif
