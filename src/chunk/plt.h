#ifndef EGALITO_CHUNK_PLT_H
#define EGALITO_CHUNK_PLT_H

#include <map>
#include "types.h"
#include "elf/reloc.h"

class Chunk;
class Symbol;

/*class PLT {
private:
    address_t entry;
    Chunk *target;
    Symbol *targetSymbol;
public:
    PLT(address_t entry, Symbol *targetSymbol)
        : entry(entry), target(nullptr), targetSymbol(targetSymbol) {}

    address_t getAddress() const { return entry; }
    Chunk *getTarget() const { return target; }
    Symbol *getTargetSymbol() const { return targetSymbol; }
};*/

class PLTRegistry {
private:
    typedef std::map<address_t, Reloc *> RegistryType;
    RegistryType registry;
public:
    void add(address_t address, Reloc *r) { registry[address] = r; }
    Reloc *find(address_t address);
};

#endif
