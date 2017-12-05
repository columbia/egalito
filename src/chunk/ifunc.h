#ifndef EGALITO_CHUNK_IFUNC_H
#define EGALITO_CHUNK_IFUNC_H

#include <vector>
#include <map>
#include "chunk.h"
#include "chunklist.h"
#include "link.h"

class IFunc : public ChunkImpl {
private:
    Link *link;
public:
    IFunc(Chunk *target) : link(new ExternalNormalLink(target)) {}
    address_t getAddress() const { return link->getTargetAddress(); }
    Link *getLink() const { return link; }
    void setLink(Link *link) { this->link = link; }
    virtual void accept(ChunkVisitor *visitor) {}
};

class IFuncList : public CollectionChunkImpl<IFunc> {
public:
    using IFuncType = void *(*)();
private:
    std::map<address_t, IFunc *> map;
public:
    void addIFuncFor(address_t address, Chunk *target);
    IFuncType getFor(address_t address) const;
    virtual void accept(ChunkVisitor *visitor) {}
};

#endif
