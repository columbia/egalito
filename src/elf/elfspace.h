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
class SharedLibList;
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

    void findDependencies(SharedLibList *libraryList);
    void findSymbolsAndRelocs();

    ElfMap *getElfMap() const { return elf; }
    SharedLib *getLibrary() const { return library; }
    Module *getModule() const { return module; }
    void setModule(Module *module) { this->module = module; }

    std::string getName() const;

    SymbolList *getSymbolList() const { return symbolList; }
    SymbolList *getDynamicSymbolList() const { return dynamicSymbolList; }
    RelocList *getRelocList() const { return relocList; }
    DwarfUnwindInfo *getDwarfInfo() const { return dwarf; }

    FunctionAliasMap *getAliasMap() const { return aliasMap; }
    void setAliasMap(FunctionAliasMap *aliasMap) { this->aliasMap = aliasMap; }
};

class ElfSpaceList {
private:
    std::vector<ElfSpace *> spaceList;
public:
    void add(ElfSpace *space) { spaceList.push_back(space); }

    ConcreteIterable<std::vector<ElfSpace *>> iterable()
        { return ConcreteIterable<std::vector<ElfSpace *>>(spaceList); }
};

#endif
