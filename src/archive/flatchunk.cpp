#include <cassert>
#include "flatchunk.h"

void FlatChunkList::newFlatChunk(uint16_t type) {
    newFlatChunk(FlatChunk(type, flatList.size(), /*offset=*/ 0));
}
void FlatChunkList::newFlatChunk(FlatChunk flat) {
    flatList.push_back(flat);
}

void FlatChunkList::appendData(const std::string &newData) {
    assert(flatList.size() > 0);

    flatList.back().appendData(newData);
}

void FlatChunkList::append32(uint32_t value) {
    assert(flatList.size() > 0);

    flatList.back().appendData(static_cast<void *>(&value), sizeof(value));
}
