#ifndef EGALITO_GENERATE_MAKE_PLT_H
#define EGALITO_GENERATE_MAKE_PLT_H

#include "chunk/plt.h"
#include <elf.h>

class ElfSpace;
class SymbolTableSection;
class Reloc;

class MakeOriginalPLT {
private:
    std::string pltData;
    std::string relocData;
public:
    void makePLT(ElfSpace *space, PLTList *pltList,
        SymbolTableSection *dynsym);

    const std::string &getPLTData() const { return pltData; }
    const std::string &getRelocations() const { return relocData; }
private:
    static Elf64_Rela makeRela(Reloc *r, uint64_t addend,
        size_t symbolIndex);
};

#endif
