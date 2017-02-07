#ifndef EGALITO_ELF_ELFSPACE_H
#define EGALITO_ELF_ELFSPACE_H

#include "symbol.h"
#include "reloc.h"
#include "chunk/plt.h"
#include "chunk/concrete.h"  // for Module

class ElfMap;

/** This is an internal class that stores all the information we collect
    about an ELF file, lists and maps etc. The more public ones are accessible
    from ElfSpace.
*/
class ElfData {
private:
    SymbolList *symbolList;
    RelocList *relocList;
    PLTSection *pltSection;
public:
    ElfData() : symbolList(nullptr), relocList(nullptr), pltSection(nullptr) {}

    void setSymbolList(SymbolList *list) { this->symbolList = list; }
    void setRelocList(RelocList *list) { this->relocList = list; }
    void setPLTSection(PLTSection *plt) { this->pltSection = plt; }

    SymbolList *getSymbolList() const { return symbolList; }
    RelocList *getRelocList() const { return relocList; }
    PLTSection *getPLTSection() const { return pltSection; }
};

class ElfSpace {
private:
    ElfMap *elfMap;
    ElfData data;
    Module *module;
public:
    ElfSpace(ElfMap *elfMap) : elfMap(elfMap), module(nullptr) {}

    ElfMap *getElfMap() const { return elfMap; }
    ElfData *getData() { return &data; }
    Module *getModule() const { return module; }
    void setModule(Module *module) { this->module = module; }

    SymbolList *getSymbolList() const { return data.getSymbolList(); }
    RelocList *getRelocList() const { return data.getRelocList(); }
    PLTSection *getPLTSection() const { return data.getPLTSection(); }
};

#endif
