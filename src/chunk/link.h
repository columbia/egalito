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
    enum LinkScope {
        SCOPE_UNKNOWN           = 0,
        SCOPE_WITHIN_FUNCTION   = 1 << 0,  // e.g. short jump
        SCOPE_WITHIN_SECTION    = 1 << 1,  // code-to-code links
        SCOPE_WITHIN_MODULE     = 1 << 2,  // inside the same ELF

        SCOPE_INTERNAL_JUMP     = SCOPE_WITHIN_FUNCTION
            | SCOPE_WITHIN_SECTION | SCOPE_WITHIN_MODULE,
        SCOPE_EXTERNAL_JUMP     = SCOPE_WITHIN_SECTION | SCOPE_WITHIN_MODULE,
        SCOPE_INTERNAL_DATA     = SCOPE_WITHIN_MODULE,
        SCOPE_EXTERNAL_DATA     = 0,
        SCOPE_EXTERNAL_CODE     = 0,
    };
public:
    virtual ~Link() {}

    /** Returns target as a Chunk, if possible. May return NULL. */
    virtual ChunkRef getTarget() const = 0;
    virtual address_t getTargetAddress() const = 0;

    virtual LinkScope getScope() const = 0;
    virtual bool isExternalJump() const = 0;
    virtual bool isWithinModule() const = 0;
};

template <Link::LinkScope Scope, typename BaseType>
class LinkScopeDecorator : public BaseType {
public:
    virtual Link::LinkScope getScope() const { return Scope; }
    virtual bool isExternalJump() const
        { return !matches(Link::SCOPE_WITHIN_FUNCTION); }
    virtual bool isWithinModule() const
        { return matches(Link::SCOPE_WITHIN_MODULE); }
private:
    bool matches(Link::LinkScope s) const
        { return (Scope & s) == s; }
};

class LinkImpl : public Link {
private:
    Link::LinkScope scope;
public:
    LinkImpl(Link::LinkScope scope) : scope(scope) {}

    virtual Link::LinkScope getScope() const { return scope; }
    virtual bool isExternalJump() const
        { return !matches(Link::SCOPE_WITHIN_FUNCTION); }
    virtual bool isWithinModule() const
        { return matches(Link::SCOPE_WITHIN_MODULE); }

    void setScope(Link::LinkScope scope) { this->scope = scope; }
private:
    bool matches(Link::LinkScope s) const
        { return (scope & s) == s; }
};


// --- standard Chunk links ---

/** A relative reference to another Chunk.

    The source and destination address may both be updated for this Link.
*/
class NormalLink : public LinkImpl {
private:
    ChunkRef target;
public:
    NormalLink(ChunkRef target, Link::LinkScope scope)
        : LinkImpl(scope), target(target) {}

    virtual ChunkRef getTarget() const { return target; }
    virtual address_t getTargetAddress() const;
};

/** An absolute reference to another Chunk.

    Here the source address is irrelevant to getTargetAddress().
*/
class AbsoluteNormalLink : public NormalLink {
public:
    using NormalLink::NormalLink;
};

/** Stores a link to a target Chunk, offset a given number of bytes from
    its start. This is used to target into an instruction that has a LOCK
    prefix on x86_64, for example.
*/
class OffsetLink : public LinkImpl {
private:
    ChunkRef target;
    size_t offset;
public:
    OffsetLink(ChunkRef target, size_t offset, Link::LinkScope scope)
        : LinkImpl(scope), target(target), offset(offset) {}

    virtual ChunkRef getTarget() const { return target; }
    virtual address_t getTargetAddress() const;
};


// --- special Chunk links ---

class PLTTrampoline;
class PLTLink : public LinkScopeDecorator<
    Link::SCOPE_WITHIN_MODULE, Link> {
private:
    address_t originalAddress;
    PLTTrampoline *pltTrampoline;
public:
    PLTLink(address_t originalAddress, PLTTrampoline *pltTrampoline)
        : originalAddress(originalAddress), pltTrampoline(pltTrampoline) {}

    PLTTrampoline *getPLTTrampoline() const { return pltTrampoline; }
    virtual ChunkRef getTarget() const;
    virtual address_t getTargetAddress() const;
};

class JumpTable;
class JumpTableLink : public LinkScopeDecorator<
    Link::SCOPE_WITHIN_MODULE, Link> {
private:
    JumpTable *jumpTable;
public:
    JumpTableLink(JumpTable *jumpTable) : jumpTable(jumpTable) {}

    virtual ChunkRef getTarget() const;
    virtual address_t getTargetAddress() const;
};

class Symbol;
class SymbolOnlyLink : public LinkScopeDecorator<
    Link::SCOPE_WITHIN_MODULE, Link> {
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

class EgalitoLoaderLink : public LinkScopeDecorator<
    Link::SCOPE_EXTERNAL_CODE, Link> {
private:
    std::string targetName;
public:
    EgalitoLoaderLink(const std::string &name) : targetName(name) {}

    const std::string &getTargetName() const { return targetName; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const;
};

// Only used for executable generation
class LDSOLoaderLink : public LinkScopeDecorator<
    Link::SCOPE_EXTERNAL_CODE, Link> {
private:
    std::string targetName;
public:
    LDSOLoaderLink(const std::string &name) : targetName(name) {}

    const std::string &getTargetName() const { return targetName; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const { return 0; }
};


class StackLink : public LinkScopeDecorator<
    Link::SCOPE_UNKNOWN, Link> {
private:
    address_t targetAddress;
public:
    StackLink(address_t target) : targetAddress(target) {}

    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const { return targetAddress; }
};

class Marker;
class MarkerLink : public LinkScopeDecorator<
    Link::SCOPE_UNKNOWN, Link> {
private:
    Marker *marker;

public:
    MarkerLink(Marker *marker) : marker(marker) {}

    Marker *getMarker() const { return marker; }
    virtual ChunkRef getTarget() const { return nullptr; }
    virtual address_t getTargetAddress() const;
};

class AbsoluteMarkerLink : public MarkerLink {
public:
    using MarkerLink::MarkerLink;
};

class GSTableEntry;
class GSTableLink : public LinkScopeDecorator<
    Link::SCOPE_UNKNOWN, Link> {
private:
    GSTableEntry *entry;
public:
    GSTableLink(GSTableEntry *entry) : entry(entry) {}

    GSTableEntry *getEntry() const { return entry; }
    virtual ChunkRef getTarget() const;
    virtual address_t getTargetAddress() const;
};

class DistanceLink : public LinkScopeDecorator<
    Link::SCOPE_UNKNOWN, Link> {
private:
    ChunkRef base;
    ChunkRef target;
public:
    DistanceLink(ChunkRef base, ChunkRef target) : base(base), target(target) {}
    virtual ChunkRef getTarget() const;
    virtual address_t getTargetAddress() const; // distance
};

// --- data links ---

class DataSection;
class DataOffsetLink : public LinkImpl {
private:
    DataSection *section;
    address_t target;
    size_t addend;
public:
    DataOffsetLink(DataSection *section, address_t target,
        Link::LinkScope scope = Link::SCOPE_INTERNAL_DATA)
        : LinkImpl(scope), section(section), target(target), addend(0) {}

    void setAddend(size_t addend) { this->addend = addend; }
    virtual ChunkRef getTarget() const;
    virtual address_t getTargetAddress() const;
};

class AbsoluteDataLink : public DataOffsetLink {
public:
    using DataOffsetLink::DataOffsetLink;
};

class TLSDataRegion;
class TLSDataOffsetLink : public LinkScopeDecorator<Link::SCOPE_WITHIN_MODULE,
    Link> {
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
    address_t getRawTarget() const { return target; }
};

// --- other links ---

/** We know that this is a Link, but we're not sure what it points at yet.
*/
class UnresolvedLink : public LinkScopeDecorator<
    Link::SCOPE_UNKNOWN, Link> {
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

    virtual Link::LinkScope getScope() const
        { throw "ImmAndDispLink not handled"; }
    virtual bool isExternalJump() const { throw "ImmAndDispLink not handled"; }
    virtual bool isWithinModule() const { throw "ImmAndDispLink not handled"; }
};


// --- link factory ---

class Module;
class LinkFactory {
public:
    static Link *makeNormalLink(ChunkRef target, bool isRelative = true,
        bool isExternal = false);
    static Link *makeDataLink(Module *module, address_t target,
        bool isRelative = true);
    static Link *makeMarkerLink(Module *module, Symbol *symbol, size_t addend,
        bool isRelative);
    static Link *makeInferredMarkerLink(Module *module, address_t address,
        bool isRelative);
};

// --- link resolver ---

class Reloc;
class Instruction;
class Conductor;
class ElfSpace;
class ExternalSymbol;
class SymbolVersion;

/** This resolver assumes that we have both relocations and symbols.
 */
class PerfectLinkResolver {
public:
    /* Resolve within the same module using address info in a relocation.
     * Only returns nullptr if undefined within the module. */
    Link *resolveInternally(Reloc *reloc, Module *module, bool weak,
        bool relative=true);

    /* Resolve outside the module using symbol info. */
    Link *resolveExternally(Symbol *symbol, Conductor *conductor,
        ElfSpace *elfSpace, bool weak, bool relative, bool afterMapping=false);
    Link *resolveExternally(ExternalSymbol *externalSymbol, Conductor *conductor,
        ElfSpace *elfSpace, bool weak, bool relative, bool afterMapping=false);

    /* Resolve within the same module using address obtained by data flow
     * analysis. */
    Link *resolveInferred(address_t address, Instruction *instruction,
        Module *module, bool relative);

private:
    Link *resolveExternally2(const char *name, const SymbolVersion *version,
        Conductor *conductor, ElfSpace *elfSpace, bool weak, bool relative,
        bool afterMapping);
    Link *resolveNameAsLinkHelper(const char *name, const SymbolVersion *version,
        ElfSpace *space, bool weak, bool relative, bool afterMapping);
    Link *resolveNameAsLinkHelper2(const char *name, ElfSpace *space,
        bool weak, bool relative, bool afterMapping);
};

#endif
