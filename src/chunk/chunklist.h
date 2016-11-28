#ifndef EGALITO_CHUNK_CHUNK_LIST_H
#define EGALITO_CHUNK_CHUNK_LIST_H

#include <vector>
#include <map>
#include <string>
#include "chunk.h"
#include "util/iter.h"
#include "types.h"

class ChunkList {
public:
    virtual ~ChunkList() {}

    //virtual void add(Chunk *child) = 0;

    //virtual IterableImpl<Chunk *> iterable() = 0;
};

template <typename ChildType, typename ParentType = ChunkList>
class IterableChunkList : public ParentType {
private:
    typedef std::vector<ChildType *> ChildListType;
    ChildListType childList;
public:
    IterableImpl<ChildListType> iterable() { return childList; }

    virtual void add(ChildType *child) { childList.push_back(child); }
};

#if 0
template <typename ChildType, typename ParentType = ChunkList>
class SearchableChunkList : public ParentType {
private:
    typedef std::set<ChildType *> ChildSetType;
    ChildSetType childSet;
public:
    virtual void add(ChildType *child)
        { ParentType::add(child); childSet.insert(child); }

    bool contains(ChildType *child)
        { return childSet.find(child) != childSet.end(); }
};
#endif

template <typename ChildType, typename ParentType = ChunkList>
class SpatialChunkList : public ParentType {
private:
    typedef std::map<address_t, ChildType *> SpaceMapType;
    SpaceMapType spaceMap;
public:
    virtual void add(ChildType *child)
        { ParentType::add(child); spaceMap[child->getPosition().get()] = child; }

    ChildType *find(address_t address);
};

template <typename ChildType, typename ParentType = ChunkList>
class NamedChunkList : public ParentType {
private:
    typedef std::map<std::string, ChildType *> NameMapType;
    NameMapType nameMap;
public:
    virtual void add(ChildType *child)
        { ParentType::add(child); nameMap[child->getName()] = child; }

    ChildType *find(const std::string &name);
};

template <typename ChunkType, typename ParentType>
ChunkType *NamedChunkList<ChunkType, ParentType>::find(const std::string &name) {
    auto it = nameMap.find(name);
    return (it != nameMap.end() ? (*it).second : nullptr);
}

template <typename ChunkType, typename ParentType>
ChunkType *SpatialChunkList<ChunkType, ParentType>::find(address_t address) {
    auto it = spaceMap.find(address);
    return (it != spaceMap.end() ? (*it).second : nullptr);
}

typedef IterableChunkList<Chunk> DefaultChunkList;

template <typename ChildType>
class ElfChunkList : public NamedChunkList<
    ChildType, IterableChunkList<ChildType>> {};

#if 0
template <typename ChildType>
class SearchableChunkList : public ChunkList<ChildType> {
private:
    typedef std::set<ChildType *> ChildSetType;
    ChildSetType childSet;
public:
    virtual void add(ChildType *child)
        { ChunkList<ChildType>::add(child); childSet.insert(child); }

    bool contains(ChildType *child)
        { return childSet.find(child) != childSet.end(); }
};





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

    IterableImpl<ChunkType *> iterable()
        { return IterableImpl<ChunkType *>(chunkList); }
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

#endif
