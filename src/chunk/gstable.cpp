#include <cassert>
#include "gstable.h"
#include "chunk/function.h"
#include "conductor/setup.h"
#include "operation/find2.h"
#include "log/log.h"

extern ConductorSetup *egalito_conductor_setup;

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
    // reserve index 0 for future use
    return entryMap.size() + 1;
}

GSTableEntry::IndexType GSTable::offsetToIndex(GSTableEntry::IndexType offset) {
    return offset / ENTRY_SIZE;
}

GSTableEntry *GSTable::getAtIndex(GSTableEntry::IndexType index) {
    index -= 1;
    if(index >= getChildren()->getIterable()->getCount()) {
        LOG(0, "table overflow?");
        return nullptr;
    }

    return getChildren()->getIterable()->get(index);
}

void GSTable::accept(ChunkVisitor *visitor) {
    // NYI
}
