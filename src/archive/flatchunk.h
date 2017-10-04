#ifndef EGALITO_ARCHIVE_FLAT_CHUNK_H
#define EGALITO_ARCHIVE_FLAT_CHUNK_H

#include <cstdint>
#include <string>
#include <vector>
#include "types.h"

class Chunk;

class FlatChunk {
public:
    typedef uint16_t FlatType;
    typedef uint32_t IDType;
    typedef uint32_t OffsetType;
private:
    FlatType type;
    IDType id;
    OffsetType offset;
    std::string data;
    Chunk *instance;
public:
    FlatChunk();
    FlatChunk(FlatType type, IDType id, std::string data = "")
        : type(type), id(id), offset(0), data(data), instance(nullptr) {}

    FlatType getType() const { return type; }
    IDType getID() const { return id; }
    OffsetType getOffset() const { return offset; }
    uint32_t getSize() const { return data.length(); }
    std::string getData() const { return data; }

    template <typename ChunkType>
    ChunkType *getInstance() const { return dynamic_cast<ChunkType *>(instance); }

    void appendData(const std::string &newData) { data += newData; }
    void appendData(const void *newData, size_t newSize)
        { data.append(static_cast<const char *>(newData), newSize); }

    void setOffset(uint32_t offset) { this->offset = offset; }
    void setInstance(Chunk *instance) { this->instance = instance; }
};

class FlatChunkList {
private:
    typedef std::vector<FlatChunk *> FlatListType;
    FlatListType flatList;
    FlatChunk::IDType nextID;
public:
    FlatChunkList() : nextID(0) {}
    ~FlatChunkList();

    FlatChunk *newFlatChunk(uint16_t type);
    FlatChunk *newFlatChunk(uint16_t type, FlatChunk::IDType id);
    void addFlatChunk(FlatChunk *flat);

    FlatChunk *get(FlatListType::size_type i);
    FlatChunk::IDType getNextID() { return nextID ++; }
    size_t getCount() const { return flatList.size(); }

    FlatListType::iterator begin() { return flatList.begin(); }
    FlatListType::iterator end() { return flatList.end(); }
    FlatListType::const_iterator begin() const { return flatList.cbegin(); }
    FlatListType::const_iterator end() const { return flatList.cend(); }
    FlatListType::reverse_iterator rbegin() { return flatList.rbegin(); }
    FlatListType::reverse_iterator rend() { return flatList.rend(); }
};

#endif
