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
    Chunk *otherTarget;
public:
    GSTableEntry(Chunk *target, uint32_t index)
        : target(target), index(index), otherTarget(nullptr) {}

    Chunk *getTarget() const { return target; }
    IndexType getIndex() const { return index; }
    IndexType getOffset() const;
    void setOtherTarget(Chunk *other) { otherTarget = other; }
    Chunk *getOtherTarget() const { return otherTarget; }

    virtual void accept(ChunkVisitor *visitor);
};

class GSTable : public CollectionChunkImpl<GSTableEntry> {
private:
    //Chunk *escapeTarget;
    std::map<Chunk *, GSTableEntry *> entryMap;
    void *tableAddress;
    void *signalTableAddress;
    size_t reserved;
public:
    GSTable()
        : /* escapeTarget(nullptr), */ tableAddress(nullptr), signalTableAddress(nullptr), reserved(0) {}

    // no going back
    void finishReservation();
    GSTableEntry::IndexType getJITStartIndex() const { return reserved; }

    GSTableEntry *makeReservedEntryFor(Chunk *target);
    GSTableEntry *makeJITEntryFor(Chunk *target);
    GSTableEntry *getEntryFor(Chunk *target);
    //void setEscapeTarget(Chunk *target) { escapeTarget = target; }

    GSTableEntry::IndexType offsetToIndex(GSTableEntry::IndexType offset);
    GSTableEntry *getAtIndex(GSTableEntry::IndexType index);

    void setTableAddress(void *address) { tableAddress = address; }
    void *getTableAddress() const { return tableAddress; }

    void setSignalTableAddress(void *address) { signalTableAddress = address; }
    void *getSignalTableAddress() const { return signalTableAddress; }

    virtual void accept(ChunkVisitor *visitor);
private:
    GSTableEntry *makeEntryFor(Chunk *target);
    GSTableEntry::IndexType nextIndex() const { return entryMap.size(); }
    bool reserving() const { return reserved == 0; }
};

#endif
