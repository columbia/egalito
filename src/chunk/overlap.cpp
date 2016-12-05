#include <utility>
#include "overlap.h"

void ChunkOverlapSearch::add(Chunk *chunk) {
    rangeList.push_back(std::make_pair(chunk->getRange(), chunk));
}

Chunk *ChunkOverlapSearch::find(const Range &range) {
    for(auto i : rangeList) {
        if(i.first.contains(range)) return i.second;
    }

    return nullptr;
}
