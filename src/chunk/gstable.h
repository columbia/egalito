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
    IndexType index;
public:
    GSTableEntry(Chunk *target, uint32_t index)
        : target(target), index(index) {}

    Chunk *getTarget() const { return target; }
    IndexType getIndex() const { return index; }
    IndexType getOffset() const;

    virtual void accept(ChunkVisitor *visitor);
};

class GSTable : public CollectionChunkImpl<GSTableEntry> {
private:
    Chunk *escapeTarget;
    std::map<Chunk *, GSTableEntry *> entryMap;
public:
    GSTable() : escapeTarget(nullptr) {}

    GSTableEntry *makeEntryFor(Chunk *target);
    void setEscapeTarget(Chunk *target) { escapeTarget = target; }

    virtual void accept(ChunkVisitor *visitor);
private:
    GSTableEntry::IndexType nextIndex() const;
};

#endif
