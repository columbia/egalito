#ifndef EGALITO_CHUNK_CHUNK_LIST_H
#define EGALITO_CHUNK_CHUNK_LIST_H

#include <vector>
#include <map>
#include <string>
#include "chunk.h"
#include "util/iter.h"
#include "types.h"

template <typename ChildType>
class IterableChunkList;
template <typename ChildType>
class SpatialChunkList;
template <typename ChildType>
class NamedChunkList;

template <typename ChildType>
class ChunkList {
public:
    virtual ~ChunkList() {}
    virtual IterableChunkList<ChildType> *getIterable() = 0;
    virtual SpatialChunkList<ChildType> *getSpatial() = 0;
    virtual NamedChunkList<ChildType> *getByName() = 0;
};

template <typename ChildType>
class ChunkListImpl : public ChunkList<ChildType> {
private:
    IterableChunkList<ChildType> iterable;
    SpatialChunkList<ChildType> *spatial;
    NamedChunkList<ChildType> *named;
public:
    ChunkListImpl() : spatial(nullptr), named(nullptr) {}
    virtual ~ChunkListImpl() { delete spatial, delete named; }

    virtual void add(ChildType child);
    virtual IterableChunkList<ChildType> *getIterable() { return &iterable; }
    virtual SpatialChunkList<ChildType> *getSpatial() { return spatial; }
    virtual NamedChunkList<ChildType> *getByName() { return named; }

    void setSpatial(SpatialChunkList<ChildType> *s) { spatial = s; }
    void setNamed(NamedChunkList<ChildType> *n) { named = n; }
};

template <typename ChildType>
void ChunkListImpl<ChildType>::add(ChildType child) {
    iterable.add(child);
    if(spatial) spatial->add(child);
    if(named) named->add(child);
}

template <typename ChildType>
class IterableChunkList {
private:
    typedef std::vector<ChildType *> ChildListType;
    ChildListType childList;
public:
    ConcreteIterable<ChildListType> iterable() { return childList; }

    void add(ChildType *child) { childList.push_back(child); }

    ChildType *get(size_t index) { return childList[index]; }
    ChildType *getLast() { return childList[childList.size() - 1]; }
    void insertAt(size_t index, ChildType *child)
        { childList.insert(childList.begin() + index, child); }
    size_t getCount() const { return childList.size(); }
};

template <typename ChildType>
class SpatialChunkList {
private:
    typedef std::map<address_t, ChildType *> SpaceMapType;
    SpaceMapType spaceMap;
public:
    ConcreteIterable<SpaceMapType, std::pair<address_t, ChildType *>> iterable() { return spaceMap; }
    void add(ChildType *child)
        { spaceMap[child->getAddress()] = child; }

    ChildType *find(address_t address);
};

template <typename ChunkType>
ChunkType *SpatialChunkList<ChunkType>::find(address_t address) {
    auto it = spaceMap.find(address);
    return (it != spaceMap.end() ? (*it).second : nullptr);
}

template <typename ChildType>
class NamedChunkList {
private:
    typedef std::map<std::string, ChildType *> NameMapType;
    NameMapType nameMap;
public:
    void add(ChildType *child)
        { nameMap[child->getName()] = child; }

    ChildType *find(const std::string &name);
};

template <typename ChunkType>
ChunkType *NamedChunkList<ChunkType>::find(const std::string &name) {
    auto it = nameMap.find(name);
    return (it != nameMap.end() ? (*it).second : nullptr);
}

template <typename ChildType>
class ElfChunkList : public ChunkList<ChildType> {};

#endif
