#ifndef EGALITO_CHUNK_PLT_H
#define EGALITO_CHUNK_PLT_H

#include <map>
#include "types.h"
#include "elf/reloc.h"

class ElfMap;
class Chunk;
class Symbol;

class PLTEntry {
private:
    ElfMap *sourceElf;
    address_t entry;
    Chunk *target;
    Symbol *targetSymbol;
public:
    PLTEntry(ElfMap *sourceElf, address_t entry, Symbol *targetSymbol)
        : sourceElf(sourceElf), entry(entry), target(nullptr),
        targetSymbol(targetSymbol) {}

    address_t getAddress() const { return entry; }
    ElfMap *getSourceElf() const { return sourceElf; }
    Chunk *getTarget() const { return target; }
    Symbol *getTargetSymbol() const { return targetSymbol; }
    std::string getName() const;
};

class PLTSection {
private:
    RelocList *relocList;
    std::map<address_t, PLTEntry *> entryMap;
public:
    PLTSection(RelocList *relocList) : relocList(relocList) {}
    void parse(ElfMap *elf);

    PLTEntry *find(address_t address);
private:
    void parsePLTGOT(ElfMap *elf);
};

#endif
