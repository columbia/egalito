#ifndef EGALITO_ARCHIVE_FLAT_CHUNK_H
#define EGALITO_ARCHIVE_FLAT_CHUNK_H

#include <cstdint>
#include <string>
#include <vector>
#include "types.h"

class Chunk;

class FlatChunk {
private:
    uint16_t type;
    uint32_t id;
    uint32_t offset;
    std::string data;
    Chunk *instance;
public:
    FlatChunk(uint16_t type, uint32_t id, uint32_t offset,
        std::string data = "")
        : type(type), id(id), offset(offset), data(data) {}

    uint16_t getType() const { return type; }
    uint32_t getID() const { return id; }
    uint32_t getOffset() const { return offset; }
    uint32_t getSize() const { return data.length(); }
    std::string getData() const { return data; }
    void appendData(const std::string &newData) { data += newData; }
    void appendData(const void *newData, size_t newSize)
        { data.append(static_cast<const char *>(newData), newSize); }

    void setOffset(uint32_t offset) { this->offset = offset; }
    void setInstance(Chunk *instance) { this->instance = instance; }

    template <typename ChunkType>
    ChunkType *getInstance() const { return dynamic_cast<ChunkType *>(instance); }
};

class FlatChunkList {
private:
    typedef std::vector<FlatChunk> FlatListType;
    FlatListType flatList;
public:
    void newFlatChunk(uint16_t type);
    void newFlatChunk(FlatChunk flat);
    void appendData(const std::string &newData);
    void append32(uint32_t value);

    FlatChunk &get(FlatListType::size_type i);

    FlatListType::iterator begin() { return flatList.begin(); }
    FlatListType::iterator end() { return flatList.end(); }
    FlatListType::const_iterator begin() const { return flatList.cbegin(); }
    FlatListType::const_iterator end() const { return flatList.cend(); }

    size_t getCount() const { return flatList.size(); }
};

#endif
