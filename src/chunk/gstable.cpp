#include <cassert>
#include "gstable.h"
#include "log/log.h"


#define ENTRY_SIZE 8

GSTableEntry::IndexType GSTableEntry::getOffset() const {
    return index * ENTRY_SIZE;
}

void GSTableEntry::accept(ChunkVisitor *visitor) {
    // NYI
}

GSTableEntry *GSTable::makeEntryFor(Chunk *target, bool preResolved) {
    auto entry = getEntryFor(target);
    if(!entry) {
        if(preResolved) {
            entry = new GSTableResolvedEntry(target, nextIndex());
        }
        else {
            entry = new GSTableEntry(target, nextIndex());
        }
        getChildren()->add(entry);
        entryMap[target] = entry;
    }
    return entry;
}

GSTableEntry *GSTable::getEntryFor(Chunk *target) {
    auto it = entryMap.find(target);
    if(it != entryMap.end()) {
        return (*it).second;
    }
    return nullptr;
}

GSTableEntry::IndexType GSTable::nextIndex() const {
    return entryMap.size();
}

GSTableEntry::IndexType GSTable::offsetToIndex(GSTableEntry::IndexType offset) {
    return offset / ENTRY_SIZE;
}

GSTableEntry *GSTable::getAtIndex(GSTableEntry::IndexType index) {
    if(index >= getChildren()->getIterable()->getCount()) {
        LOG(1, "table overflow?");
        return nullptr;
    }

    return getChildren()->getIterable()->get(index);
}

void GSTable::accept(ChunkVisitor *visitor) {
    // NYI
}
