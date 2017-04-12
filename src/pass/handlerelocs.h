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
    virtual void visit(Instruction *instruction) {}
private:
    void handleRelocation(Reloc *r, FunctionList *functionList,
        Function *target);
    void handleRelocation(Reloc *r, FunctionList *functionList,
                                        Symbol *symbol);


};

#endif
