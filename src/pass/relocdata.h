#ifndef EGALITO_PASS_RELOCDATA_H
#define EGALITO_PASS_RELOCDATA_H

#include "chunkpass.h"
#include "elf/reloc.h"

class ElfMap;
class ElfSpace;
class Conductor;

class FindAnywhere {
private:
    Conductor *conductor;
    ElfSpace *elfSpace;
    Function *found;
public:
    FindAnywhere(Conductor *conductor, ElfSpace *elfSpace)
        : conductor(conductor), elfSpace(elfSpace), found(nullptr) {}

    Function *findAnywhere(const char *target);
    Function *findInside(Module *module, const char *target);

    ElfSpace *getElfSpace() const { return elfSpace; }

    address_t getRealAddress();
};

/** Fixes relocations in the data section prior to running code.

    This must be called after all libraries have been parsed and contain
    a FunctionAliasMap.
*/
class RelocDataPass : public ChunkPass {
private:
    ElfMap *elf;
    ElfSpace *elfSpace;
    RelocList *relocList;
    Conductor *conductor;
    Module *module;
public:
    RelocDataPass(ElfMap *elf, ElfSpace *elfSpace, RelocList *relocList,
        Conductor *conductor)
        : elf(elf), elfSpace(elfSpace), relocList(relocList),
        conductor(conductor) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction) {}
private:
    bool resolveFunction(const char *name, address_t *address);
    bool resolveLocalDataRef(const char *name, address_t *address);
    bool resolveGen2(const char *name, address_t *address);
    bool resolveGen2Helper(const char *name, address_t *address,
        ElfSpace *space);
    void fixRelocation(Reloc *r);
};

#endif
