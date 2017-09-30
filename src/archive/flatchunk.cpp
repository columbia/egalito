#include <cassert>
#include "flatchunk.h"
#include "archive.h"  // for TYPE_UNKNOWN
#include "log/log.h"

FlatChunk::FlatChunk() : type(EgalitoArchive::TYPE_UNKNOWN), id(-1), offset(0),
    data() {
}

FlatChunk *FlatChunkList::newFlatChunk(uint16_t type) {
    flatList.push_back(new FlatChunk(type, flatList.size()));
    return flatList.back();
}

FlatChunkList::~FlatChunkList() {
    for(auto flat : flatList) delete flat;
}

void FlatChunkList::addFlatChunk(FlatChunk *flat) {
    flatList.resize(flat->getID() + 1);
    if(flatList[flat->getID()] && flatList[flat->getID()]->getID()) {
        LOG(1, "WARNING: overwriting old FlatChunk at ID " << flat->getID());
    }
    flatList[flat->getID()] = flat;
}

FlatChunk *FlatChunkList::get(FlatListType::size_type i) {
    assert(i < flatList.size());
    return flatList[i];
}
