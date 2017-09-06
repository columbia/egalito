#ifndef EGALITO_CHUNK_DATA_REGION_H
#define EGALITO_CHUNK_DATA_REGION_H

#include <vector>
#include "chunk.h"
#include "chunklist.h"
#include "util/iter.h"
#include "elf/elfxx.h"

class Link;
class ElfMap;

class DataRegion;

class DataVariable : public AddressableChunkImpl {
private:
    Link *dest;
    size_t addend;
public:
    DataVariable(DataRegion *region, address_t address, Link *dest);

    Link *getDest() const { return dest; }
    void setDest(Link *dest) { this->dest = dest; }

    void setAddend(size_t addend) { this->addend = addend; }
    size_t getAddend() const { return addend; }

    virtual void accept(ChunkVisitor *visitor) {}
};

class DataSection : public CompositeChunkImpl<DataVariable> {
private:
    size_t size;
    size_t align;
    address_t originalOffset;
    bool bss;

public:
    DataSection(ElfXX_Phdr *phdr, ElfXX_Shdr *shdr);
    virtual size_t getSize() const { return size; }
    size_t getAlignment() const { return align; }
    address_t getOriginalOffset() const { return originalOffset; }
    bool isBss() const { return bss; }
    virtual std::string getName() const;
    virtual void accept(ChunkVisitor *visitor) {}
};

class DataRegion : public CompositeChunkImpl<DataSection> {
private:
    typedef std::vector<DataVariable *> VariableListType;
    VariableListType variableList;
    ElfXX_Phdr *phdr;
    address_t originalAddress;
    size_t startOffset;
    address_t mappedAddress;
public:
    DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr);
    virtual ~DataRegion() {}

    virtual std::string getName() const;

    ElfXX_Phdr *getPhdr() const { return phdr; }

    void addVariable(DataVariable *variable);
    bool contains(address_t address);
    bool endsWith(address_t address);
    bool writable() const { return phdr->p_flags & PF_W; }
    bool executable() const { return phdr->p_flags & PF_X; }
    bool bssOnly() const { return phdr->p_filesz == 0; }
    size_t getDataSize() const { return phdr->p_filesz - startOffset; }
    size_t getBssSize() const { return phdr->p_memsz - phdr->p_filesz; }
    size_t getAlignment() const { return phdr->p_align; }

    virtual void updateAddressFor(address_t baseAddress);
    address_t getOriginalAddress() const { return originalAddress; }
    size_t getStartOffset() const { return startOffset; }
    address_t getMapBaseAddress() const { return mappedAddress; }

    ConcreteIterable<VariableListType> variableIterable()
        { return ConcreteIterable<VariableListType>(variableList); }
    DataVariable *findVariable(address_t address) const;

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
