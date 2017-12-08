#ifndef EGALITO_ELF_ELFSPACE_H
#define EGALITO_ELF_ELFSPACE_H

#include <string>
#include "symbol.h"
#include "reloc.h"
#include "dwarf/entry.h"
#include "chunk/plt.h"
#include "chunk/concrete.h"  // for Module
#include "util/iter.h"

class ElfMap;
class FunctionAliasMap;

class ElfSpace {
private:
    ElfMap *elf;
    DwarfUnwindInfo *dwarf;
    std::string name;
    std::string fullPath;
    Module *module;
private:
    SymbolList *symbolList;
    SymbolList *dynamicSymbolList;
    RelocList *relocList;
    FunctionAliasMap *aliasMap;
public:
    ElfSpace(ElfMap *elf, const std::string &name,
        const std::string &fullPath);
    ~ElfSpace();

    void findSymbolsAndRelocs();

    ElfMap *getElfMap() const { return elf; }
    Module *getModule() const { return module; }
    void setModule(Module *module) { this->module = module; }

    std::string getName() const { return name; }
    std::string getFullPath() const { return name; }

    SymbolList *getSymbolList() const { return symbolList; }
    SymbolList *getDynamicSymbolList() const { return dynamicSymbolList; }
    RelocList *getRelocList() const { return relocList; }
    DwarfUnwindInfo *getDwarfInfo() const { return dwarf; }

    FunctionAliasMap *getAliasMap() const { return aliasMap; }
    void setAliasMap(FunctionAliasMap *aliasMap) { this->aliasMap = aliasMap; }
private:
    std::string getAlternativeSymbolFile() const;
};

#if 0
class ElfSpaceList {
private:
    std::vector<ElfSpace *> spaceList;
public:
    void add(ElfSpace *space) { spaceList.push_back(space); }

    ConcreteIterable<std::vector<ElfSpace *>> iterable()
        { return ConcreteIterable<std::vector<ElfSpace *>>(spaceList); }
};
#endif

#endif
