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
    address_t gotPLTEntry;
public:
    PLTTrampoline(ElfMap *sourceElf, address_t address, Symbol *targetSymbol,
                  address_t gotPLTEntry);

    std::string getName() const;

    ElfMap *getSourceElf() const { return sourceElf; }
    Chunk *getTarget() const { return target; }
    Symbol *getTargetSymbol() const { return targetSymbol; }

    void setTarget(Chunk *target) { this->target = target; }

    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }

    void writeTo(char *target);
    address_t getGotPLTEntry() const
        { return sourceElf->getBaseAddress() + gotPLTEntry; }
};

class PLTSection {
public:
    PLTList *parse(RelocList *relocList, ElfMap *elf);
    static bool parsePLTList(ElfMap *elf, RelocList *relocList, Module *module);
private:
    void parsePLTGOT(RelocList *relocList, ElfMap *elf,
        PLTList *pltList);
};

class ElfSpace;
class MakeOriginalPLT {
private:
    std::string pltData;
    std::string relocData;
public:
    void makePLT(ElfSpace *space, PLTList *pltList);

    const std::string &getPLTData() const { return pltData; }
    const std::string &getRelocations() const { return relocData; }
};

#endif
