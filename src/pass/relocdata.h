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
public:
    FindAnywhere(Conductor *conductor)
        : conductor(conductor), elfSpace(nullptr) {}

    Function *findAnywhere(const char *target);

    ElfSpace *getElfSpace() const { return elfSpace; }
};

/** Fixes relocations in the data section prior to running code.

    This must be called after all libraries have been parsed and contain
    a FunctionAliasMap.
*/
class RelocDataPass : public ChunkPass {
private:
    ElfMap *elf;
    RelocList *relocList;
    Conductor *conductor;
public:
    RelocDataPass(ElfMap *elf, RelocList *relocList,
        Conductor *conductor)
        : elf(elf), relocList(relocList), conductor(conductor) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction) {}
};

#endif
