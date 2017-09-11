#ifndef EGALITO_CHUNK_MARKER_H
#define EGALITO_CHUNK_MARKER_H

#include "chunk/chunk.h"
#include "chunk/chunklist.h"
#include "elf/symbol.h"

class Module;
class RelocList;

class Marker : public AddressableChunkImpl {
private:
    Symbol *symbol;
    DataSection *dataSection;
    size_t alignment;

public:
    Marker(Symbol *symbol);
    Marker(DataSection *dataSection, size_t alignment);
    Symbol *getSymbol() const { return symbol; }
    DataSection *getDataSection() const { return dataSection; }
    size_t getAlignment() const { return alignment; }
    address_t inferAddress() const;
    virtual void accept(ChunkVisitor *visitor) {}
};

class MarkerList : public CollectionChunkImpl<Marker> {
public:
    MarkerList() {}

    static MarkerList *buildMarkerList(ElfMap *elf, Module *module,
        SymbolList *symbolList, RelocList *relocList);
    static MarkerLink *makeMarkerLink(Module *module, Symbol *symbol);
    static MarkerLink *makeMarkerLink(Module *module, DataSection *dataSection,
        size_t alignment);

    virtual void accept(ChunkVisitor *visitor);
};

#endif
