#ifndef EGALITO_CHUNK_PLT_H
#define EGALITO_CHUNK_PLT_H

#include <map>
#include "chunk.h"
#include "chunklist.h"
#include "elf/reloc.h"
#include "types.h"

class ElfMap;
class Chunk;
class Symbol;

class PLTTrampoline : public CompositeChunkImpl<Instruction> {
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

    bool isIFunc() const;
    void writeTo(char *target);
    address_t getGotPLTEntry() const
        { return sourceElf->getBaseAddress() + gotPLTEntry; }

    virtual void accept(ChunkVisitor *visitor);
};

class Module;
class PLTList : public CollectionChunkImpl<PLTTrampoline> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);
public:
    static size_t getPLTTrampolineSize();
    static PLTList *parse(RelocList *relocList, ElfMap *elf, Module *modle);
    static bool parsePLTList(ElfMap *elf, RelocList *relocList, Module *module);
private:
    static void parsePLTGOT(RelocList *relocList, ElfMap *elf,
        PLTList *pltList);
};

#endif
