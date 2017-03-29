#ifndef EGALITO_CHUNK_PLT_H
#define EGALITO_CHUNK_PLT_H

#include <map>
#include "elf/reloc.h"
#include "concrete.h"
#include "types.h"

class ElfMap;
class Chunk;
class Symbol;

class PLTTrampoline : public ChunkImpl {
private:
    ElfMap *sourceElf;
    Chunk *target;
    Symbol *targetSymbol;
    char *gotPLTEntry;
public:
    PLTTrampoline(ElfMap *sourceElf, address_t address, Symbol *targetSymbol);
    PLTTrampoline(ElfMap *sourceElf, address_t address, Symbol *targetSymbol,
                  char *gotPLTEntry);

    std::string getName() const;

    ElfMap *getSourceElf() const { return sourceElf; }
    Chunk *getTarget() const { return target; }
    Symbol *getTargetSymbol() const { return targetSymbol; }

    void setTarget(Chunk *target) { this->target = target; }

    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }

    void writeTo(char *target);
    char *getGotPLTEntry() const {
        return sourceElf->getBaseAddress() + gotPLTEntry; }
};

class PLTSection {
public:
    PLTList *parse(RelocList *relocList, ElfMap *elf);
    static bool parsePLTList(ElfMap *elf, RelocList *relocList, Module *module);
private:
    void parsePLTGOT(RelocList *relocList, ElfMap *elf,
        PLTList *pltList);
};

#endif
