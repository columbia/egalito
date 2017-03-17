#ifndef EGALITO_PASS_RELOCDATA_H
#define EGALITO_PASS_RELOCDATA_H

#include "chunkpass.h"
#include "elf/reloc.h"

class ElfMap;
class ElfSpace;
class Conductor;

#if 0
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
#endif

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
    /** Tries to resolve the address that the named entity lives at.
        On success, sets address and returns true. On failure, returns false.
    */
    bool resolveName(const char *name, address_t *address);
    bool resolveNameHelper(const char *name, address_t *address,
        ElfSpace *space);
    void fixRelocation(Reloc *r);
};

#endif
