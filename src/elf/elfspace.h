#ifndef EGALITO_ELF_ELFSPACE_H
#define EGALITO_ELF_ELFSPACE_H

#include "symbol.h"
#include "reloc.h"
#include "dwarf/entry.h"
#include "chunk/plt.h"
#include "chunk/concrete.h"  // for Module
#include "util/iter.h"

class ElfMap;
class SharedLib;
class LibraryList;
class FunctionAliasMap;

class ElfSpace {
private:
    ElfMap *elf;
    DwarfUnwindInfo *dwarf;
    SharedLib *library;
    Module *module;
private:
    SymbolList *symbolList;
    SymbolList *dynamicSymbolList;
    RelocList *relocList;
    FunctionAliasMap *aliasMap;
public:
    ElfSpace(ElfMap *elf, SharedLib *library);
    ~ElfSpace();

    void findDependencies(LibraryList *libraryList);
    void buildDataStructures(bool hasRelocs = true);

    ElfMap *getElfMap() const { return elf; }
    SharedLib *getLibrary() const { return library; }
    Module *getModule() const { return module; }
    void setModule(Module *module) { this->module = module; }

    std::string getName() const;

    SymbolList *getSymbolList() const { return symbolList; }
    SymbolList *getDynamicSymbolList() const { return dynamicSymbolList; }
    RelocList *getRelocList() const { return relocList; }

    FunctionAliasMap *getAliasMap() const { return aliasMap; }
};

class ElfSpaceList {
private:
    ElfSpace *main;
    ElfSpace *egalito;
    std::vector<ElfSpace *> spaceList;
public:
    ElfSpaceList() : main(nullptr) {}

    void add(ElfSpace *space) { spaceList.push_back(space); }
    void setMain(ElfSpace *space) { main = space; }
    void setEgalito(ElfSpace *space) { egalito = space; }

    ConcreteIterable<std::vector<ElfSpace *>> iterable()
        { return ConcreteIterable<std::vector<ElfSpace *>>(spaceList); }
    ElfSpace *getMain() const { return main; }
    ElfSpace *getEgalito() const { return egalito; }
};

#endif
