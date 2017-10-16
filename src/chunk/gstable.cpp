#include <cassert>
#include "gstable.h"

#define ENTRY_SIZE 8

GSTableEntry::IndexType GSTableEntry::getOffset() const {
    return index * ENTRY_SIZE;
}

void GSTableEntry::accept(ChunkVisitor *visitor) {
    // NYI
}

GSTableEntry *GSTable::makeEntryFor(Chunk *target) {
    auto it = entryMap.find(target);
    if(it != entryMap.end()) {
        return (*it).second;
    }
    else {
        auto entry = new GSTableEntry(target, nextIndex());
        getChildren()->add(entry);
        entryMap[target] = entry;
        return entry;
    }
}

GSTableEntry::IndexType GSTable::nextIndex() const {
    // reserve index 0 for future use
    return entryMap.size() + 1;
}

GSTableEntry::IndexType GSTable::offsetToIndex(GSTableEntry::IndexType offset) {
    return offset / ENTRY_SIZE;
}

GSTableEntry *GSTable::getAtIndex(GSTableEntry::IndexType index) {
    index -= 1;
    if(index >= getChildren()->getIterable()->getCount()) {
        return nullptr;
    }

    return getChildren()->getIterable()->get(index);
}

void GSTable::accept(ChunkVisitor *visitor) {
    // NYI
}
