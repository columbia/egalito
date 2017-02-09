#ifndef EGALITO_ELF_ELFSPACE_H
#define EGALITO_ELF_ELFSPACE_H

#include "symbol.h"
#include "reloc.h"
#include "chunk/plt.h"
#include "chunk/concrete.h"  // for Module
#include "util/iter.h"

class ElfMap;
class SharedLib;
class LibraryList;

class ElfSpace {
private:
    ElfMap *elf;
    SharedLib *library;
    Module *module;
private:
    SymbolList *symbolList;
    SymbolList *dynamicSymbolList;
    RelocList *relocList;
    PLTSection *pltSection;
public:
    ElfSpace(ElfMap *elf, SharedLib *library);

    void findDependencies(LibraryList *libraryList);
    void inferSymbols();
    void buildDataStructures(bool hasRelocs = true);

    ElfMap *getElfMap() const { return elf; }
    SharedLib *getLibrary() const { return library; }
    Module *getModule() const { return module; }
    void setModule(Module *module) { this->module = module; }

    std::string getName() const;

    SymbolList *getSymbolList() const { return symbolList; }
    RelocList *getRelocList() const { return relocList; }
    PLTSection *getPLTSection() const { return pltSection; }
};

class ElfSpaceList {
private:
    ElfSpace *main;
    std::vector<ElfSpace *> spaceList;
public:
    ElfSpaceList() : main(nullptr) {}

    void add(ElfSpace *space, bool isMain = false);

    ConcreteIterable<std::vector<ElfSpace *>> iterable()
        { return ConcreteIterable<std::vector<ElfSpace *>>(spaceList); }
    ElfSpace *getMain() const { return main; }
};

#endif
