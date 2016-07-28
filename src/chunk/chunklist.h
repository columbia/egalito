#ifndef EGALITO_CHUNK_CHUNK_LIST_H
#define EGALITO_CHUNK_CHUNK_LIST_H

#include <vector>
#include <map>
#include <string>
#include "chunk.h"
#include "types.h"

template <typename ChunkType>
class ChunkList {
private:
    typedef std::vector<ChunkType *> ListType;
    ListType chunkList;
    typedef std::map<std::string, ChunkType *> MapType;
    MapType chunkMap;
    std::map<address_t, ChunkType *> spaceMap;
public:
    bool add(ChunkType *chunk);
    ChunkType *find(const char *name);
    ChunkType *find(address_t address);

    typename ListType::iterator begin() { return chunkList.begin(); }
    typename ListType::iterator end() { return chunkList.end(); }
};

template <typename ChunkType>
bool ChunkList<ChunkType>::add(ChunkType *chunk) {
    auto it = chunkMap.find(chunk->getName());
    if(it != chunkMap.end()) return false;

    chunkList.push_back(chunk);
    chunkMap[chunk->getName()] = chunk;
    spaceMap[chunk->getAddress()] = chunk;
    return true;
}

template <typename ChunkType>
ChunkType *ChunkList<ChunkType>::find(const char *name) {
    auto it = chunkMap.find(name);
    return (it != chunkMap.end() ? (*it).second : nullptr);
}

template <typename ChunkType>
ChunkType *ChunkList<ChunkType>::find(address_t address) {
    auto it = spaceMap.find(address);
    return (it != spaceMap.end() ? (*it).second : nullptr);
}

#endif
