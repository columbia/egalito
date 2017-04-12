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

class AbsoluteNormalLink : public NormalLink {
public:
    using NormalLink::NormalLink;
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

template <typename BaseType>
class ExternalLinkDecorator : public BaseType {
public:
    ExternalLinkDecorator(ChunkRef target) : BaseType(target) {}
};
template <>
class ExternalLinkDecorator<OffsetLink> : public OffsetLink {
public:
    ExternalLinkDecorator(ChunkRef target, size_t offset)
        : OffsetLink(target, offset) {}
};

typedef ExternalLinkDecorator<NormalLink> ExternalNormalLink;
typedef ExternalLinkDecorator<OffsetLink> ExternalOffsetLink;


class PLTTrampoline;
class PLTLink : public Link {
private:
    address_t originalAddress;
    PLTTrampoline *pltTrampoline;
public:
    PLTLink(address_t originalAddress, PLTTrampoline *pltTrampoline)
        : originalAddress(originalAddress), pltTrampoline(pltTrampoline) {}

    PLTTrampoline *getPLTTrampoline() const { return pltTrampoline; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const;
};

class JumpTable;
class JumpTableLink : public Link {
private:
    JumpTable *jumpTable;
public:
    JumpTableLink(JumpTable *jumpTable) : jumpTable(jumpTable) {}

    virtual ChunkRef getTarget() const;
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
    virtual address_t getTargetAddress() const;
};

class AbsoluteDataLink : public Link {
private:
    ElfMap *elf;
    address_t target;
public:
    AbsoluteDataLink(ElfMap *elf, address_t target)
        : elf(elf), target(target) {}

    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const;
};

class ImmAndDispLink : public Link {
private:
    NormalLink *immLink;
    Link *dispLink;
public:
    ImmAndDispLink(NormalLink *immLink, Link *dispLink)
        : immLink(immLink), dispLink(dispLink) {}
    NormalLink *getImmLink() const { return immLink; }
    Link *getDispLink() const { return dispLink; }

    // arbitrarily choose to use the displacement link
    /*virtual ChunkRef getTarget() const { return dispLink->getTarget(); }
    virtual address_t getTargetAddress() const
        { return dispLink->getTargetAddress(); }*/
    virtual ChunkRef getTarget() const { throw "ImmAndDispLink not handled"; }
    virtual address_t getTargetAddress() const { throw "ImmAndDispLink not handled"; }
};

/** We know that this is a Link, but we're not sure what it points at yet.
*/
class UnresolvedLink : public Link {
private:
    address_t target;
public:
    UnresolvedLink(address_t target) : target(target) {}

    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const { return target; }
};

class Symbol;

class SymbolOnlyLink : public Link {
private:
    Symbol *symbol;
    address_t target;
public:

    SymbolOnlyLink(Symbol *symbol, address_t target) : symbol(symbol), target(target) {}

    Symbol *getSymbol() const { return symbol; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const { return target; }
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
