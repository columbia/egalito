#ifndef EGALITO_CHUNK_OVERLAP_H
#define EGALITO_CHUNK_OVERLAP_H

#include <vector>
#include "chunk.h"

class ChunkOverlapSearch {
private:
    std::vector<std::pair<Range, Chunk *>> rangeList;
public:
    ChunkOverlapSearch() {}
    ChunkOverlapSearch(Chunk *chunk) { add(chunk); }

    void add(Chunk *chunk);

    template <typename ChunkType>
    void addChildren(ChunkType *chunk);

    Chunk *find(const Range &range);
};

template <typename ChunkType>
void ChunkOverlapSearch::addChildren(ChunkType *chunk) {
    for(auto c : chunk->getChildren()->iterable()) {
        add(c);
    }
}

#endif
