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

    virtual void updateAddressFor(address_t baseAddress);
    address_t getOriginalAddress() const { return originalAddress; }

    ConcreteIterable<VariableListType> variableIterable()
        { return ConcreteIterable<VariableListType>(variableList); }

    virtual void accept(ChunkVisitor *visitor);
};

class TLSDataRegion : public DataRegion {
public:
    using DataRegion::DataRegion;

    virtual std::string getName() const;

    virtual void updateAddressFor(address_t baseAddress);
};

class ElfMap;
class Module;
class Reloc;
class DataRegionList : public CollectionChunkImpl<DataRegion> {
private:
    DataRegion *tls;
public:
    void setTLS(DataRegion *tls) { this->tls = tls; }
    DataRegion *getTLS() const { return tls; }

    virtual void accept(ChunkVisitor *visitor);

    Link *createDataLink(address_t target, bool isRelative = true);
    DataRegion *findRegionContaining(address_t target);
    Link *resolveVariableLink(Reloc *reloc);

    static void buildDataRegionList(ElfMap *elfMap, Module *module);
};

#endif
