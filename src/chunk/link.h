#ifndef EGALITO_CHUNK_LINK_H
#define EGALITO_CHUNK_LINK_H

#include <vector>
#include <string>
#include "chunkref.h"
#include "util/iter.h"
#include "types.h"

class ElfMap;

/** Represents a reference from a Chunk that may need to be updated.

    Some Links refer to a target Chunk, and the offset may change if either
    the source or destination are moved. Others store a fixed target address,
    which again involves some recomputation if the source Chunk moves.
*/
class Link {
public:
    virtual ~Link() {}

    /** Returns target as a Chunk, if possible. May return NULL. */
    virtual ChunkRef getTarget() const = 0;
    virtual address_t getTargetAddress() const = 0;
};

/** A reference to another Chunk. */
class NormalLink : public Link {
private:
    ChunkRef target;
public:
    NormalLink(ChunkRef target) : target(target) {}

    virtual ChunkRef getTarget() const { return target; }
    virtual address_t getTargetAddress() const;
};

/** Stores a link to a target Chunk, offset a given number of bytes from
    its start. This is used to target into an instruction that has a LOCK
    prefix on x86_64, for example.
*/
class OffsetLink : public Link {
private:
    ChunkRef target;
    size_t offset;
public:
    OffsetLink(ChunkRef target, size_t offset)
        : target(target), offset(offset) {}

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
    virtual address_t getTargetAddress() const;
};

class DataOffsetLink : public Link {
private:
    ElfMap *elf;
    address_t target;
public:
    DataOffsetLink(ElfMap *elf, address_t target)
        : elf(elf), target(target) {}

    virtual ChunkRef getTarget() const { return nullptr; }
    address_t getTargetAddress() const;
};

/** We know that this is a Link, but we're not sure what it points at yet.
*/
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
