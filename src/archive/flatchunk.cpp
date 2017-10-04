#include <cassert>
#include "flatchunk.h"
#include "chunktypes.h"  // for TYPE_UNKNOWN
#include "log/log.h"

FlatChunk::FlatChunk() : type(TYPE_UNKNOWN), id(-1), offset(0), data() {
}

FlatChunk *FlatChunkList::newFlatChunk(uint16_t type) {
    return newFlatChunk(type, getNextID());
}

FlatChunk *FlatChunkList::newFlatChunk(uint16_t type, FlatChunk::IDType id) {
    auto flat = new FlatChunk(type, id);
    addFlatChunk(flat);
    return flat;
}

FlatChunkList::~FlatChunkList() {
    for(auto flat : flatList) delete flat;
}

void FlatChunkList::addFlatChunk(FlatChunk *flat) {
    if(flatList.size() < flat->getID() + 1) {
        flatList.resize(flat->getID() + 1);
    }
    if(flatList[flat->getID()]) {
        LOG(1, "WARNING: overwriting old FlatChunk at ID " << flat->getID());
    }
    flatList[flat->getID()] = flat;
    LOG(11, "add flatchunk id=" << flat->getID() << " to list");
}

FlatChunk *FlatChunkList::get(FlatListType::size_type i) {
    assert(i < flatList.size());
    return flatList[i];
}
