#ifndef EGALITO_CHUNK_VTABLE_H
#define EGALITO_CHUNK_VTABLE_H

#include <string>
#include "chunk.h"
#include "chunklist.h"
#include "archive/chunktypes.h"

class VTableEntry : public ChunkSerializerImpl<TYPE_VTableEntry,
    AddressableChunkImpl> {
private:
    Link *link;
public:
    VTableEntry(Link *link = nullptr) : link(link) {}

    Link *getLink() const { return link; }
    void setLink(Link *link) { this->link = link; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class VTable : public ChunkSerializerImpl<TYPE_VTable,
    CompositeChunkImpl<VTableEntry>> {
private:
    std::string className;
public:
    VTable() : className("???") {}

    virtual std::string getName() const;
    std::string getClassName() const { return className; }

    void setClassName(const std::string &name) { className = name; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class VTableList : public ChunkSerializerImpl<TYPE_VTableList,
    CollectionChunkImpl<VTable>> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual std::string getName() const { return "vtablelist"; }
    virtual void accept(ChunkVisitor *visitor);
};

#endif
