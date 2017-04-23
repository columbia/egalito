#ifndef EGALITO_CHUNK_DATA_REGION_H
#define EGALITO_CHUNK_DATA_REGION_H

#include <vector>
#include "chunk.h"
#include "chunklist.h"
#include "util/iter.h"

class Link;

class DataRegion : public ChunkImpl {
private:
    typedef std::vector<Link *> LinkListType;
    LinkListType linkList;
public:
    void addLink(Link *link);
    void removeLink(Link *link);

    ConcreteIterable<LinkListType> linkIterable()
        { return ConcreteIterable<LinkListType>(linkList); }

    virtual void accept(ChunkVisitor *visitor);
};

class DataRegionList : public CompositeChunkImpl<DataRegion> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);
};

#endif
