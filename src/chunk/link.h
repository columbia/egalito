#ifndef EGALITO_CHUNK_LINK_H
#define EGALITO_CHUNK_LINK_H

#include <vector>
#include <string>
#include "chunkref.h"
#include "util/iter.h"
#include "types.h"

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


// --- standard Chunk links ---

/** A relative reference to another Chunk.

    The source and destination address may both be updated for this Link.
*/
class NormalLink : public Link {
private:
    ChunkRef target;
public:
    NormalLink(ChunkRef target) : target(target) {}

    virtual ChunkRef getTarget() const { return target; }
    virtual address_t getTargetAddress() const;
};

/** An absolute reference to another Chunk.

    Here the source address is irrelevant.
*/
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

/** Indicates that a Link targets outside the current function. */
template <typename BaseType>
class ExternalLinkDecorator : public BaseType {
public:
    using BaseType::BaseType;
};

typedef ExternalLinkDecorator<NormalLink> ExternalNormalLink;
typedef ExternalLinkDecorator<AbsoluteNormalLink> ExternalAbsoluteNormalLink;
typedef ExternalLinkDecorator<OffsetLink> ExternalOffsetLink;


// --- special Chunk links ---

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

class Symbol;
class SymbolOnlyLink : public Link {
private:
    Symbol *symbol;
    address_t target;
public:
    SymbolOnlyLink(Symbol *symbol, address_t target)
        : symbol(symbol), target(target) {}

    Symbol *getSymbol() const { return symbol; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const { return target; }
};

class Marker;
class MarkerLink : public Link {
private:
    Marker *marker;
public:
    MarkerLink(Marker *marker) : marker(marker) {}

    Marker *getMarker() const { return marker; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const;
};

// --- data links ---

class DataSection;
class DataOffsetLink : public Link {
private:
    DataSection *section;
    address_t target;
public:
    DataOffsetLink(DataSection *section, address_t target)
        : section(section), target(target) {}

    virtual ChunkRef getTarget() const;
    virtual address_t getTargetAddress() const;
};

class AbsoluteDataLink : public DataOffsetLink {
public:
    using DataOffsetLink::DataOffsetLink;
};

class TLSDataRegion;
class TLSDataOffsetLink : public Link {
private:
    TLSDataRegion *tls;
    Symbol *symbol;
    address_t target;
public:
    TLSDataOffsetLink(TLSDataRegion *tls, Symbol *symbol, address_t target)
        : tls(tls), symbol(symbol), target(target) {}

    virtual ChunkRef getTarget() const;
    virtual address_t getTargetAddress() const;
    Symbol *getSymbol() const { return symbol; }
    TLSDataRegion *getTLSRegion() const { return tls; }
    void setTLSRegion(TLSDataRegion *tls) { this->tls = tls; }
    void setTarget(address_t target) { this->target = target; }
};


// --- other links ---

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

/** Some x86_64 instructions can contain two links.

    Most Link-processing code for Instructions needs to handle this case
    specially.
*/
class ImmAndDispLink : public Link {
private:
    NormalLink *immLink;
    Link *dispLink;
public:
    ImmAndDispLink(NormalLink *immLink, Link *dispLink)
        : immLink(immLink), dispLink(dispLink) {}
    NormalLink *getImmLink() const { return immLink; }
    Link *getDispLink() const { return dispLink; }

    virtual ChunkRef getTarget() const { throw "ImmAndDispLink not handled"; }
    virtual address_t getTargetAddress() const { throw "ImmAndDispLink not handled"; }
};


// --- link factory ---

class Module;
class LinkFactory {
public:
    static Link *makeNormalLink(ChunkRef target, bool isRelative = true,
        bool isExternal = false);
    static Link *makeDataLink(Module *module, address_t target,
        bool isRelative = true);
};

#endif
