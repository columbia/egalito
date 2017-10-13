#include "gstable.h"

GSTableEntry::IndexType GSTableEntry::getOffset() const {
    return index * 8;
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

void GSTable::accept(ChunkVisitor *visitor) {
    // NYI
}
