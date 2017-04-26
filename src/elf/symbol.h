#ifndef EGALITO_SYMBOL_H
#define EGALITO_SYMBOL_H

#include <cstddef>  // for size_t
#include <map>
#include <vector>
#include <string>
#include "types.h"

class ElfMap;
class SharedLib;

class Symbol {
public:
    enum SymbolType {
        TYPE_FUNC,
        TYPE_IFUNC,
        TYPE_OBJECT,
        TYPE_SECTION,
        TYPE_FILE,
        TYPE_UNKNOWN
    };
    enum BindingType {
        BIND_LOCAL,
        BIND_GLOBAL,
        BIND_WEAK
    };
    // Only applicable for ARM architectures
    enum MappingType {
        MAPPING_ARM,
        MAPPING_THUMB,
        MAPPING_AARCH64,
        MAPPING_DATA
    };

private:
    address_t address;
    size_t size;
    const char *name;
    Symbol *aliasFor;
    std::vector<Symbol *> aliasList;
    SymbolType symbolType;
    BindingType bindingType;
    MappingType mappingType;
    size_t index;
    size_t shndx;
public:
    Symbol(address_t address, size_t size, const char *name,
           SymbolType sym, BindingType bind, size_t index, size_t shndx)
        : address(address), size(size), name(name), aliasFor(nullptr),
        symbolType(sym), bindingType(bind), index(index), shndx(shndx) {}

    address_t getAddress() const { return address; }
    size_t getSize() const { return size; }
    const char *getName() const { return name; }
    SymbolType getType() const { return symbolType; }
    BindingType getBind() const { return bindingType; }
    Symbol *getAliasFor() const { return aliasFor; }
    size_t getSectionIndex() const { return shndx; }
    size_t getIndex() const { return index; }

    void setSize(size_t size) { this->size = size; }
    void setAliasFor(Symbol *aliasFor) { this->aliasFor = aliasFor; }
    void setType(SymbolType type) { this->symbolType = type; }

    void addAlias(Symbol *alias) { aliasList.push_back(alias); }

    const std::vector<Symbol *> &getAliases() const { return aliasList; }

    bool isFunction() const;

    MappingType getMappingType() const { return mappingType; }
    void setMappingType(MappingType type) { this->mappingType = type; }
    bool isMappingSymbol() const;

 public:
    static unsigned char typeFromInternalToElf(SymbolType type);
    static SymbolType typeFromElfToInternal(unsigned char type);
    static unsigned char bindFromInternalToElf(BindingType bind);
    static BindingType bindFromElfToInternal(unsigned char bind);
    static MappingType mappingFromElfToInternal(unsigned char type);
};

class SymbolList {
private:
    typedef std::vector<Symbol *> ListType;
    ListType symbolList;
    ListType sortedSymbolList;
    typedef std::vector<Symbol *> IndexMapType;
    IndexMapType indexMap;
    typedef std::map<std::string, Symbol *> MapType;
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

    size_t estimateSizeOf(Symbol *symbol);

    static SymbolList *buildSymbolList(SharedLib *library);
    static SymbolList *buildSymbolList(ElfMap *elfmap);
    static SymbolList *buildDynamicSymbolList(ElfMap *elfmap);
private:
    static SymbolList *buildAnySymbolList(ElfMap *elfmap,
        const char *sectionName, unsigned sectionType);
    static Symbol *findSizeZero(SymbolList *list, const char *sym);
    void sortSymbols();
};

// Only applicable for ARM architectures
class MappingSymbolList {
private:
    typedef std::vector<Symbol *> ListType;
    ListType symbolList;
    typedef std::map<address_t, Symbol *> MapType;
    MapType symbolMap;
public:
    ListType::iterator begin() { return symbolList.begin(); }
    ListType::iterator end() { return symbolList.end(); }
    size_t getCount() const { return symbolList.size(); }
    bool add(Symbol *symbol);
    Symbol *find(address_t address);
    static MappingSymbolList *buildMappingSymbolList(SymbolList *symbolList);
};

#endif
