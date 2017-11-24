#ifndef EGALITO_CHUNK_VTABLE_H
#define EGALITO_CHUNK_VTABLE_H

#include <string>
#include "chunk.h"
#include "chunklist.h"

class VTable : public AddressableChunkImpl {
private:
    DataOffsetLink *vtableLink;
    DataOffsetLink *typeinfoLink;
    std::string className;
public:
    VTable() : vtableLink(nullptr), typeinfoLink(nullptr), className("???") {}

    std::string getName() const;

    DataOffsetLink *getVTableLink() const { return vtableLink; }
    DataOffsetLink *getTypeinfoLink() const { return typeinfoLink; }
    std::string getClassName() const { return className; }

    void setVTableLink(DataOffsetLink *link) { vtableLink = link; }
    void setTypeinfoLink(DataOffsetLink *link) { typeinfoLink = link; }
    void setClassName(const std::string &name) { className = name; }

    virtual void accept(ChunkVisitor *visitor);
};

class VTableList : public CollectionChunkImpl<VTable> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);
};

#endif
