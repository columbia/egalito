#ifndef EGALITO_CHUNK_PLT_H
#define EGALITO_CHUNK_PLT_H

#include <map>
#include "chunk.h"
#include "chunklist.h"
#include "block.h"
#include "archive/chunktypes.h"
#include "elf/reloc.h"
#include "types.h"

class ElfMap;
class Chunk;
class Symbol;
class ExternalSymbol;
class ChunkCache;

class PLTTrampoline : public ChunkSerializerImpl<TYPE_PLTTrampoline,
    CompositeChunkImpl<Block>> {
private:
    ExternalSymbol *externalSymbol;
    address_t gotPLTEntry;
    ChunkCache *cache;
    bool pltGot;
public:
    PLTTrampoline() : externalSymbol(nullptr), gotPLTEntry(0),
        cache(nullptr), pltGot(false) {}
    PLTTrampoline(Chunk *pltList, address_t address,
        ExternalSymbol *externalSymbol, address_t gotPLTEntry,
        bool pltGot = false);

    std::string getName() const;

    Chunk *getTarget() const;

    ExternalSymbol *getExternalSymbol() const { return externalSymbol; }

    bool isIFunc() const;
    bool isPltGot() const { return pltGot; }
    void writeTo(char *target);
    void writeTo(std::string &target);
    address_t getGotPLTEntry() const;

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);

    void makeCache();
    ChunkCache *getCache() const { return cache; }
};

class Module;
class PLTList : public ChunkSerializerImpl<TYPE_PLTList,
    CollectionChunkImpl<PLTTrampoline>> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
public:
    static size_t getPLTTrampolineSize();
    static PLTList *parse(RelocList *relocList, ElfMap *elf, Module *module);
    static bool parsePLTList(ElfMap *elf, RelocList *relocList, Module *module);
private:
    static void parsePLTGOT(RelocList *relocList, ElfMap *elf,
        PLTList *pltList, Module *module);
};

#endif
