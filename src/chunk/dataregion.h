#ifndef EGALITO_CHUNK_DATA_REGION_H
#define EGALITO_CHUNK_DATA_REGION_H

#include <vector>
#include "chunk.h"
#include "chunklist.h"
#include "util/iter.h"
#include "elf/elfxx.h"

class Link;

class DataRegion : public ComputedSizeDecorator<AddressableChunkImpl> {
private:
    typedef std::vector<Link *> LinkListType;
    LinkListType linkList;
    ElfXX_Phdr *phdr;
public:
    DataRegion(ElfXX_Phdr *phdr);

    void addLink(Link *link);
    void removeLink(Link *link);

    ConcreteIterable<LinkListType> linkIterable()
        { return ConcreteIterable<LinkListType>(linkList); }

    virtual void accept(ChunkVisitor *visitor);
};

class ElfMap;
class Module;
class DataRegionList : public CollectionChunkImpl<DataRegion> {
private:
    DataRegion *tls;
public:
    void setTLS(DataRegion *tls) { this->tls = tls; }
    DataRegion *getTLS() const { return tls; }

    virtual void accept(ChunkVisitor *visitor);

    Link *createDataLink(address_t target, bool isRelative = true);

    static void buildDataRegionList(ElfMap *elfMap, Module *module);
};

#endif
