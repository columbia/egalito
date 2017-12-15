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

class DataVariable : public ChunkSerializerImpl<TYPE_DataVariable,
    AddressableChunkImpl> {
private:
    std::string name;
    Link *dest;
public:
    DataVariable() : dest(nullptr) {}
    DataVariable(DataRegion *region, address_t address, Link *dest);

    std::string getName() const { return name; }
    void setName(const std::string &name) { this->name = name; }

    Link *getDest() const { return dest; }
    void setDest(Link *dest) { this->dest = dest; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor) {}
};

class DataSection : public ChunkSerializerImpl<TYPE_DataSection,
    CompositeChunkImpl<DataVariable>> {
public:
    enum Type {
        TYPE_UNKNOWN,
        TYPE_BSS,
        TYPE_DATA,
        TYPE_CODE,
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

    size_t getAlignment() const { return alignment; }
    address_t getOriginalOffset() const { return originalOffset; }
    Type getType() const { return type; }
    bool isCode() const { return type == TYPE_CODE; }
    bool isBss() const { return type == TYPE_BSS; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor) {}
};

class DataRegion : public ChunkSerializerImpl<TYPE_DataRegion,
    CompositeChunkImpl<DataSection>> {
private:
    typedef std::vector<DataVariable *> VariableListType;
    VariableListType variableList;
    address_t originalAddress;
    uint32_t permissions;
    address_t alignment;
    std::string dataBytes;
public:
    DataRegion() : originalAddress(0), permissions(0), alignment(0) {}
    DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr);
    virtual ~DataRegion() {}

    virtual std::string getName() const;
    const std::string &getDataBytes() const { return dataBytes; }
    size_t getSizeOfInitializedData() const { return dataBytes.length(); }

    bool contains(address_t address);
    bool readable() const { return permissions & PF_R; }
    bool writable() const { return permissions & PF_W; }
    bool executable() const { return permissions & PF_X; }

    void updateAddressFor(address_t baseAddress);
    address_t getOriginalAddress() const { return originalAddress; }

    DataSection *findDataSectionContaining(address_t address);

    void addVariable(DataVariable *variable);
    DataVariable *findVariable(const std::string &name);
    ConcreteIterable<VariableListType> variableIterable()
        { return ConcreteIterable<VariableListType>(variableList); }
    DataVariable *findVariable(address_t address) const;

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

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    static void buildDataRegionList(ElfMap *elfMap, Module *module);
};

#endif
