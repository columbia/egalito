#ifndef EGALITO_CHUNK_MARKER_H
#define EGALITO_CHUNK_MARKER_H

#include "chunk/chunk.h"
#include "chunk/chunklist.h"
#include "elf/symbol.h"

class Module;
class RelocList;

class Marker : public ChunkImpl {
private:
    address_t address;
    Symbol *symbol;

public:
    Marker(address_t address, Symbol *symbol=nullptr);
    Symbol *getSymbol() const { return symbol; }
    void setSymbol(Symbol *symbol) { this->symbol = symbol; }
    virtual void accept(ChunkVisitor *visitor) {}

    virtual address_t getAddress() const { return address; }
    virtual void setAddress(address_t address) { this->address = address; }
};

class SectionStartMarker : public Marker {
private:
    DataSection *dataSection;
    long int bias;

public:
    SectionStartMarker(DataSection *dataSection, Symbol *symbol=nullptr);
    DataSection *getDataSection() const { return dataSection; }
    virtual void accept(ChunkVisitor *visitor) {}

    virtual address_t getAddress() const;
    virtual void setAddress(address_t address);
};

class SectionEndMarker : public Marker {
private:
    DataSection *dataSection;
    long int bias;

public:
    SectionEndMarker(DataSection *dataSection, Symbol *symbol=nullptr);
    DataSection *getDataSection() const { return dataSection; }
    virtual void accept(ChunkVisitor *visitor) {}

    virtual address_t getAddress() const;
    virtual void setAddress(address_t address);
};

class MarkerList : public CollectionChunkImpl<Marker> {
public:
    virtual void accept(ChunkVisitor *visitor);

    Link *createMarkerLink(address_t target, size_t addend, Symbol *symbol,
        Module *module);
    Marker *findOrAddGeneralMarker(address_t target, Symbol *symbol);
    Marker *findOrAddStartMarker(Symbol *symbol, DataSection *dataSection);
    Marker *findOrAddEndMarker(Symbol *symbol, DataSection *dataSection);

private:
    Link *createGeneralMarkerLink(address_t target, Symbol *symbol,
        size_t addend, Module *module);
    Link *createStartOrEndMarkerLink(address_t target, Symbol *symbol,
        size_t addend, DataSection *dataSection, Module *module);
};

#endif
