#ifndef EGALITO_RELOC_H
#define EGALITO_RELOC_H

#include <vector>
#include <map>
#include <elf.h>

#include "types.h"
#include "elf/elfmap.h"

class Reloc {
private:
    address_t address;      // source address
    uint8_t type;           // type
    uint64_t symbolIndex;   // target
    uint64_t addend;        // for RELA relocs
public:
    Reloc(address_t address, uint8_t type,
        uint64_t symbolIndex, uint64_t addend)
        : address(address), type(type),
        symbolIndex(symbolIndex), addend(addend) {}

    address_t getAddress() const { return address; }
    uint8_t getType() const { return type; }
    uint64_t getSymbolIndex() const { return symbolIndex; }
    uint64_t getAddend() const { return addend; }
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

    static RelocList buildRelocList(ElfMap *elfmap);
};

#endif
