#ifndef EGALITO_CHUNK_CHUNK_LIST_H
#define EGALITO_CHUNK_CHUNK_LIST_H

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include "chunk.h"
#include "util/iter.h"
#include "types.h"

template <typename ChildType>
class IterableChunkList;
template <typename ChildType>
class SpatialChunkList;
template <typename ChildType>
class NamedChunkList;

class ChunkList {
public:
    virtual ~ChunkList() {}
    virtual void genericAdd(Chunk *child) = 0;
    virtual Chunk *genericGetLast() = 0;
    virtual Iterable<Chunk *> genericIterable() = 0;
};

template <typename ChildType>
class ChunkListImpl : public ChunkList {
private:
    IterableChunkList<ChildType> iterable;
    SpatialChunkList<ChildType> *spatial;
    NamedChunkList<ChildType> *named;
public:
    ChunkListImpl() : spatial(nullptr), named(nullptr) {}
    virtual ~ChunkListImpl() { delete spatial, delete named; }

    virtual void genericAdd(Chunk *child)
        { auto v = dynamic_cast<ChildType *>(child); if(v) add(v); }
    virtual Chunk *genericGetLast() { return iterable.getLast(); }
    virtual Iterable<Chunk *> genericIterable() { return iterable.genericIterable(); }

    virtual void add(ChildType *child);
    virtual IterableChunkList<ChildType> *getIterable() { return &iterable; }
    virtual SpatialChunkList<ChildType> *getSpatial() { if(!spatial) createSpatial(); return spatial; }
    virtual NamedChunkList<ChildType> *getNamed() { if(!named) createNamed(); return named; }

    void createSpatial();
    void createNamed();
    void clearSpatial() { delete spatial; spatial = nullptr; }
    void clearNamed() { delete named; named = nullptr; }
};

template <typename ChildType>
void ChunkListImpl<ChildType>::add(ChildType *child) {
    iterable.add(child);
    if(spatial) spatial->add(child);
    if(named) named->add(child);
}

template <typename ChildType>
void ChunkListImpl<ChildType>::createSpatial() {
    spatial = new SpatialChunkList<ChildType>();
    for(auto c : iterable.iterable()) spatial->add(c);
}

template <typename ChildType>
void ChunkListImpl<ChildType>::createNamed() {
    named = new NamedChunkList<ChildType>();
    for(auto c : iterable.iterable()) named->add(c);
}

template <typename ChildType>
class IterableChunkList {
private:
    typedef std::vector<ChildType *> ChildListType;
    ChildListType childList;
public:
    ConcreteIterable<ChildListType> iterable() { return ConcreteIterable<ChildListType>(childList); }

    Iterable<Chunk *> genericIterable() { return Iterable<Chunk *>(new STLIteratorGenerator<ChildListType, Chunk *>(childList)); }

    void add(ChildType *child) { childList.push_back(child); }

    ChildType *get(size_t index) { return childList[index]; }
    ChildType *getLast() { return childList.size() ? childList[childList.size() - 1] : nullptr; }
    void insertAt(size_t index, ChildType *child)
        { childList.insert(childList.begin() + index, child); }
    size_t getCount() const { return childList.size(); }
    size_t indexOf(ChildType *child);
};

template <typename ChildType>
size_t IterableChunkList<ChildType>::indexOf(ChildType *child) {
    for(size_t i = 0; i < childList.size(); i ++) {
        if(child == childList[i]) return i;
    }

    return static_cast<size_t>(-1);
}

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
    ChildType *findContaining(address_t address);
    std::vector<ChildType *> findAllContaining(address_t address);
};

template <typename ChildType>
ChildType *SpatialChunkList<ChildType>::find(address_t address) {
    auto it = spaceMap.find(address);
    return (it != spaceMap.end() ? (*it).second : nullptr);
}

template <typename ChildType>
ChildType *SpatialChunkList<ChildType>::findContaining(address_t address) {
    auto it = spaceMap.upper_bound(address);
    if(it == spaceMap.begin()) return nullptr;

    it --;
    auto c = (*it).second;
    return (c->getRange().contains(address) ? c : nullptr);
}

template <typename ChildType>
std::vector<ChildType *> SpatialChunkList<ChildType>
    ::findAllContaining(address_t address) {

    std::vector<ChildType *> found;
    auto it = spaceMap.upper_bound(address);
    if(it == spaceMap.begin()) return std::move(found);

    // This is a terrible hack to only look in a neighbourhood of 5 for
    // overlapping entities. Should work since the typical case for this is
    // to detect overlapping functions, which are 2: ORIG and ORIG_nocancel.
    for(int i = 0; i < 5 && it != spaceMap.begin(); i ++) {
        it --;
        auto c = (*it).second;
        if(c->getRange().contains(address)) found.push_back(c);
    }
    return std::move(found);
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

#endif
