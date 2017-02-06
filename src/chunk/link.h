#ifndef EGALITO_CHUNK_LINK_H
#define EGALITO_CHUNK_LINK_H

#include <vector>
#include <string>
#include "chunkref.h"
#include "util/iter.h"
#include "types.h"

class Link {
public:
    virtual ~Link() {}

    virtual ChunkRef getTarget() const = 0;
    virtual address_t getTargetAddress() const = 0;
};

class NormalLink : public Link {
private:
    ChunkRef target;
public:
    NormalLink(ChunkRef target) : target(target) {}

    virtual ChunkRef getTarget() const { return target; }
    virtual address_t getTargetAddress() const;
};

class PLTEntry;
class PLTLink : public Link {
private:
    address_t originalAddress;
    PLTEntry *pltEntry;
public:
    PLTLink(address_t originalAddress, PLTEntry *pltEntry)
        : originalAddress(originalAddress), pltEntry(pltEntry) {}

    PLTEntry *getPLTEntry() const { return pltEntry; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const { return originalAddress; }
};

class UnresolvedLink : public Link {
private:
    address_t target;
public:
    UnresolvedLink(address_t target) : target(target) {}

    virtual ChunkRef getTarget() const { return nullptr; }
    address_t getTargetAddress() const { return target; }
};

class XRef {
private:
    ChunkRef source;
    Link *link;
public:
    XRef(ChunkRef source, Link *link) : source(source), link(link) {}

    ChunkRef getSource() const { return source; }
    ChunkRef getTarget() const { return link->getTarget(); }
};

class XRefDatabase {
private:
    typedef std::vector<XRef> DatabaseType;
    DatabaseType database;
public:
    void add(XRef xref) { database.push_back(xref); }

    ConcreteIterable<DatabaseType> iterable()
        { return ConcreteIterable<DatabaseType>(database); }
};

#endif
