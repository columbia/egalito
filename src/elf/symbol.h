#ifndef EGALITO_SYMBOL_H
#define EGALITO_SYMBOL_H

#include <cstddef>  // for size_t
#include <map>
#include <vector>
#include "types.h"

class ElfMap;
class SharedLib;

class Symbol {
private:
    address_t address;
    size_t size;
    std::vector<const char *> names;
public:
    Symbol(address_t address, size_t size, const char *name)
        : address(address), size(size), names({name}) {}

    address_t getAddress() const { return address; }
    size_t getSize() const { return size; }
    const char *getName() const { return names[0]; }

    void addAlias(const char *name) { names.push_back(name); }

    const std::vector<const char *> &getAliases() const { return names; }
};

class SymbolList {
private:
    typedef std::vector<Symbol *> ListType;
    ListType symbolList;
    ListType sortedSymbolList;
    typedef std::vector<Symbol *> IndexMapType;
    IndexMapType indexMap;
    typedef std::map<const char *, Symbol *> MapType;
    MapType symbolMap;
    std::map<address_t, Symbol *> spaceMap;
public:
    bool add(Symbol *symbol, size_t index);
    void addAlias(Symbol *symbol, size_t otherIndex);
    Symbol *get(size_t index);
    Symbol *find(const char *name);
    Symbol *find(address_t address);
    size_t getCount() const { return symbolList.size(); }

    ListType::iterator begin() { return symbolList.begin(); }
    ListType::iterator end() { return symbolList.end(); }

    static SymbolList *buildSymbolList(SharedLib *library);
    static SymbolList *buildSymbolList(ElfMap *elfmap);
    static SymbolList *buildDynamicSymbolList(ElfMap *elfmap);
private:
    void sortSymbols();
};

#endif
