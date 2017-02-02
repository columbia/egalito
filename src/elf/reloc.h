#ifndef EGALITO_RELOC_H
#define EGALITO_RELOC_H

#include <vector>
#include <map>
#include <elf.h>

#include "types.h"
#include "elf/elfmap.h"

class Symbol;
class SymbolList;

class Reloc {
private:
    address_t address;      // source address
    uint16_t type;          // type
    uint64_t symbolIndex;   // target index
    Symbol *symbol;         // target
    uint64_t addend;        // for RELA relocs
public:
    Reloc(address_t address, uint16_t type, uint64_t symbolIndex,
        Symbol *symbol, uint64_t addend)
        : address(address), type(type), symbolIndex(symbolIndex),
        symbol(symbol), addend(addend) {}

    address_t getAddress() const { return address; }
    uint16_t getType() const { return type; }
    Symbol *getSymbol() const { return symbol; }
    uint64_t getAddend() const { return addend; }

    std::string getSymbolName() const;
};

class RelocList {
private:
    typedef std::vector<Reloc *> ListType;
    ListType relocList;
    typedef std::map<address_t, Reloc *> MapType;
    MapType relocMap;
public:
    bool add(Reloc *reloc);

    ListType::iterator begin() { return relocList.begin(); }
    ListType::iterator end() { return relocList.end(); }

    Reloc *find(address_t address);

    static RelocList *buildRelocList(ElfMap *elfmap, SymbolList *symbolList);
};

#endif
