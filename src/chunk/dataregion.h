#ifndef EGALITO_CHUNK_DATA_REGION_H
#define EGALITO_CHUNK_DATA_REGION_H

#include <vector>
#include "chunk.h"
#include "chunklist.h"
#include "util/iter.h"
#include "elf/elfxx.h"

class Link;
class ElfMap;

// perhaps this should be a Chunk
class DataVariable {
private:
    DataRegion *region;
    address_t offset;
    Link *dest;
public:
    DataVariable(DataRegion *region, address_t offset, Link *dest)
        : region(region), offset(offset), dest(dest) {}

    address_t getAddress();
    address_t getOffset() const { return offset; }
    Link *getDest() const { return dest; }
};

class DataRegion : public ComputedSizeDecorator<AddressableChunkImpl> {
private:
    typedef std::vector<DataVariable *> VariableListType;
    VariableListType variableList;
    ElfXX_Phdr *phdr;
    address_t originalAddress;
public:
    DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr);
    virtual ~DataRegion() {}

    virtual std::string getName() const;

    ElfXX_Phdr *getPhdr() const { return phdr; }

    void addVariable(DataVariable *variable);
    bool contains(address_t address);
    bool endsWith(address_t address);

    virtual void updateAddressFor(address_t baseAddress);
    address_t getOriginalAddress() const { return originalAddress; }

    ConcreteIterable<VariableListType> variableIterable()
        { return ConcreteIterable<VariableListType>(variableList); }

    virtual void accept(ChunkVisitor *visitor);
};

/** Maintains a tlsOffset, which is the offset from the beginning of all TLS
    data to this particular TLS region.
*/
class TLSDataRegion : public DataRegion {
private:
    address_t tlsOffset;
public:
    TLSDataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr)
        : DataRegion(elfMap, phdr), tlsOffset(0) {}

    virtual std::string getName() const;

    bool containsData(address_t address);

    virtual void updateAddressFor(address_t baseAddress);

    void setTLSOffset(address_t offset) { tlsOffset = offset; }
    address_t getTLSOffset() const { return tlsOffset; }
};

class ElfMap;
class Module;
class Reloc;
class DataRegionList : public CollectionChunkImpl<DataRegion> {
private:
    TLSDataRegion *tls;
public:
    void setTLS(TLSDataRegion *tls) { this->tls = tls; }
    TLSDataRegion *getTLS() const { return tls; }

    virtual void accept(ChunkVisitor *visitor);

    Link *createDataLink(address_t target, bool isRelative = true);
    DataRegion *findRegionContaining(address_t target);
    Link *resolveVariableLink(Reloc *reloc, Module *module);

    static void buildDataRegionList(ElfMap *elfMap, Module *module);
};

#endif
