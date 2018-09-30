#ifndef EGALITO_CHUNK_DATA_REGION_H
#define EGALITO_CHUNK_DATA_REGION_H

#include <vector>
#include <string>
#include "chunk.h"
#include "chunklist.h"
#include "util/iter.h"
#include "elf/elfxx.h"
#include "archive/chunktypes.h"

class Link;
class ElfMap;
class Module;

class DataRegion;

/** Represents a variable within a global data section that points at another
    Chunk.
*/
class DataVariable : public ChunkSerializerImpl<TYPE_DataVariable,
    AddressableChunkImpl> {
private:
    std::string name;
    Link *dest;
    size_t size;    // != sizeof(address_t) for relative jump table entries
public:
    DataVariable() : dest(nullptr), size(sizeof(address_t)) {}

    // After constructing, manually append this DataVariable to its Section.
    DataVariable(DataSection *section, address_t address, Link *dest);

    std::string getName() const { return name; }
    void setName(const std::string &name) { this->name = name; }

    Link *getDest() const { return dest; }
    void setDest(Link *dest) { this->dest = dest; }

    size_t getSize() const { return size; }
    void setSize(size_t size) { this->size = size; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor); 

    static DataVariable *create(DataSection *section, address_t address,
        Link *dest, Symbol *symbol);
    static DataVariable *create(Module *module, address_t address,
        Link *dest, Symbol *symbol);
};

class DataSection : public ChunkSerializerImpl<TYPE_DataSection,
    CompositeChunkImpl<DataVariable>> {
public:
    enum Type {
        TYPE_UNKNOWN,
        TYPE_BSS,
        TYPE_DATA,
        TYPE_CODE,
        TYPE_INIT_ARRAY,
        TYPE_FINI_ARRAY,
        TYPE_DYNAMIC,
    };
private:
    std::string name;
    address_t alignment;
    address_t originalOffset;
    Type type;
public:
    DataSection() : alignment(0), originalOffset(0), type(TYPE_UNKNOWN) {}
    DataSection(ElfMap *elfMap, address_t segmentAddress, ElfXX_Shdr *shdr);

    virtual std::string getName() const;
    bool contains(address_t address);

    DataVariable *findVariable(const std::string &name);
    DataVariable *findVariable(address_t address);

    size_t getAlignment() const { return alignment; }
    address_t getOriginalOffset() const { return originalOffset; }
    Type getType() const { return type; }
    bool isCode() const { return type == TYPE_CODE; }
    bool isBss() const { return type == TYPE_BSS; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class DataRegion : public ChunkSerializerImpl<TYPE_DataRegion,
    ChildListDecorator<AddressableChunkImpl, DataSection>> {
private:
    address_t originalAddress;
    size_t size;
    uint32_t permissions;
    address_t alignment;
    std::string dataBytes;
public:
    DataRegion() : originalAddress(0), size(0), permissions(0), alignment(0) {}
    DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr);
    virtual ~DataRegion() {}

    virtual std::string getName() const;
    virtual size_t getSize() const { return size; }
    const std::string &getDataBytes() const { return dataBytes; }
    size_t getSizeOfInitializedData() const { return dataBytes.length(); }
    void saveDataBytes(bool captureUninitializedData = true);
    virtual void addToSize(diff_t add) { /* ignored */ }

    bool contains(address_t address);
    bool readable() const { return permissions & PF_R; }
    bool writable() const { return permissions & PF_W; }
    bool executable() const { return permissions & PF_X; }

    void updateAddressFor(address_t baseAddress);
    address_t getOriginalAddress() const { return originalAddress; }

    DataSection *findDataSectionContaining(address_t address);
    DataSection *findDataSection(const std::string &name);

    DataVariable *findVariable(const std::string &name);
    DataVariable *findVariable(address_t address);

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

/** Maintains a tlsOffset, which is the offset from the beginning of all TLS
    data to this particular TLS region.
*/
class TLSDataRegion : public DataRegion {
private:
    address_t tlsOffset;
public:
    TLSDataRegion() : tlsOffset(0) {}
    TLSDataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr)
        : DataRegion(elfMap, phdr), tlsOffset(0) {}

    virtual std::string getName() const;

    bool containsData(address_t address);

    void setBaseAddress(address_t baseAddress);

    void setTLSOffset(address_t offset) { tlsOffset = offset; }
    address_t getTLSOffset() const { return tlsOffset; }

    virtual size_t getFlatType() const final { return TYPE_TLSDataRegion; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);
};

class DataRegionList : public ChunkSerializerImpl<TYPE_DataRegionList,
    CollectionChunkImpl<DataRegion>> {
private:
    TLSDataRegion *tls;
public:
    DataRegionList() : tls(nullptr) {}

    void setTLS(TLSDataRegion *tls) { this->tls = tls; }
    TLSDataRegion *getTLS() const { return tls; }

    virtual void accept(ChunkVisitor *visitor);

    Link *createDataLink(address_t target, Module *module,
        bool isRelative = true);
    DataRegion *findRegionContaining(address_t target);
    DataRegion *findNonTLSRegionContaining(address_t target);

    DataSection *findDataSectionContaining(address_t address);
    DataSection *findDataSection(const std::string &name);

    DataVariable *findVariable(const std::string &name);
    DataVariable *findVariable(address_t address);

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    static void buildDataRegionList(ElfMap *elfMap, Module *module);
};

#endif
