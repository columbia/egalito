#ifndef EGALITO_CHUNK_CHUNK_LIST_H
#define EGALITO_CHUNK_CHUNK_LIST_H

#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include "chunk.h"
#include "util/iter.h"
#include "types.h"

// forward declarations
template <typename ChildType>
class IterableChunkList;
template <typename ChildType>
class SpatialChunkList;
template <typename ChildType>
class NamedChunkList;

/** Stores a list of Chunks. Primarily used for lists of children. Supports
    generic Chunk operations, but more operations are available when the child
    type is known (see ChunkListImpl).
*/
class ChunkList {
public:
    virtual ~ChunkList() {}
    virtual void genericAdd(Chunk *child) = 0;
    virtual void genericRemove(Chunk *child) = 0;
    virtual Chunk *genericGetLast() = 0;
    virtual Chunk *genericGetAt(size_t index) = 0;
    virtual void genericInsertAt(size_t index, Chunk *child) = 0;
    virtual size_t genericIndexOf(Chunk *child) = 0;
    virtual size_t genericGetSize() = 0;
    virtual Iterable<Chunk *> genericIterable() = 0;
};

/** Stores a list of Chunks of the specific type ChildType.

    There are three aspects: iterable, spatial, and named. Each aspect can
    be accessed at any point and the appropriate data structure will be
    created. Currently, the iterable data structure is always present.
*/
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
    virtual void genericRemove(Chunk *child)
        { auto v = dynamic_cast<ChildType *>(child); if(v) remove(v); }
    virtual Chunk *genericGetLast() { return iterable.getLast(); }
    virtual Chunk *genericGetAt(size_t index) { return iterable.get(index); }
    virtual void genericInsertAt(size_t index, Chunk *child)
        { auto v = dynamic_cast<ChildType *>(child); if(v) iterable.insertAt(index, v); }
    virtual size_t genericIndexOf(Chunk *child)
        { auto v = dynamic_cast<ChildType *>(child); return v ? iterable.indexOf(v) : -1; }
    virtual size_t genericGetSize() { return iterable.getCount(); }
    virtual Iterable<Chunk *> genericIterable() { return iterable.genericIterable(); }

    virtual void add(ChildType *child);
    virtual void remove(ChildType *child);
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
void ChunkListImpl<ChildType>::remove(ChildType *child) {
    iterable.remove(child);
    if(spatial) spatial->remove(child);
    if(named) named->remove(child);
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
    ConcreteIterable<ChildListType> iterable()
        { return ConcreteIterable<ChildListType>(childList); }
    Iterable<Chunk *> genericIterable()
        { return Iterable<Chunk *>(new STLIteratorGenerator<ChildListType, Chunk *>(childList)); }

    void add(ChildType *child) { childList.push_back(child); }
    void remove(ChildType *child);

    ChildType *get(size_t index) { return childList[index]; }
    ChildType *getLast() { return childList.size() ? childList[childList.size() - 1] : nullptr; }
    void insertAt(size_t index, ChildType *child)
        { childList.insert(childList.begin() + index, child); }
    size_t getCount() const { return childList.size(); }
    size_t indexOf(ChildType *child);
};

template <typename ChildType>
void IterableChunkList<ChildType>::remove(ChildType *child) {
    auto i = indexOf(child);
    if(i != static_cast<size_t>(-1)) {
        childList.erase(childList.begin() + i);
    }
}

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
    void remove(ChildType *child)
        { spaceMap.erase(child->getAddress()); }

    ChildType *find(address_t address);
    ChildType *findContaining(address_t address);
    std::vector<ChildType *> findAllContaining(address_t address);
    std::vector<ChildType *> findAllWithin(Range range);
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
std::vector<ChildType *> SpatialChunkList<ChildType>
    ::findAllWithin(Range range) {

    std::vector<ChildType *> found;
    auto it = spaceMap.upper_bound(range.getStart());
    for( ; it != spaceMap.end(); ++it) {
        auto chunk = (*it).second;
        if(range.contains(chunk->getRange())) {
            found.push_back(chunk);
        }
        else break;
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
    void remove(ChildType *child)
        { nameMap.erase(child->getName()); }

    ChildType *find(const std::string &name);
};

template <typename ChunkType>
ChunkType *NamedChunkList<ChunkType>::find(const std::string &name) {
    auto it = nameMap.find(name);
    return (it != nameMap.end() ? (*it).second : nullptr);
}

#endif
