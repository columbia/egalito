#ifndef EGALITO_CHUNK_GS_TABLE_H
#define EGALITO_CHUNK_GS_TABLE_H

#include <map>
#include "chunk.h"
#include "chunklist.h"
#include "types.h"

class GSTableEntry : public AddressableChunkImpl {
public:
    typedef uint32_t IndexType;
private:
    Chunk *target;
    Chunk *resolver;
    IndexType index;
public:
    GSTableEntry(Chunk *target, uint32_t index)
        : target(target), resolver(nullptr), index(index) {}

    virtual void setLazyResolver(Chunk *resolver) { this->resolver = resolver; }
    Chunk *getTarget() const { return resolver ? resolver : target; }
    IndexType getIndex() const { return index; }
    IndexType getOffset() const;

    // debugging
    Chunk *getRealTarget() const { return target; }

    virtual void accept(ChunkVisitor *visitor);
};

class GSTableResolvedEntry : public GSTableEntry {
    using GSTableEntry::GSTableEntry;
public:
    virtual void setLazyResolver(Chunk *resolver) {}
};

class GSTable : public CollectionChunkImpl<GSTableEntry> {
private:
    Chunk *escapeTarget;
    std::map<Chunk *, GSTableEntry *> entryMap;
    void *tableAddress;
public:
    GSTable() : escapeTarget(nullptr), tableAddress(nullptr) {}

    GSTableEntry *makeEntryFor(Chunk *target, bool preResolved = false);
    GSTableEntry *getEntryFor(Chunk *target);
    void setEscapeTarget(Chunk *target) { escapeTarget = target; }

    GSTableEntry::IndexType offsetToIndex(GSTableEntry::IndexType offset);
    GSTableEntry *getAtIndex(GSTableEntry::IndexType index);

    void setTableAddress(void *address) { tableAddress = address; }
    void *getTableAddress() const { return tableAddress; }

    virtual void accept(ChunkVisitor *visitor);
private:
    GSTableEntry::IndexType nextIndex() const;
};

#endif
