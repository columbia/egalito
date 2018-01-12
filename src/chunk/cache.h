#ifndef EGALITO_CHUNK_CACHE_H
#define EGALITO_CHUNK_CACHE_H

#include <string>
#include <vector>

#include "instr/instr.h"

class Chunk;

class ChunkCache {
private:
    address_t address;
    std::string data;
    std::vector<address_t> fixups;
public:
    ChunkCache(Chunk *chunk) { make(chunk); }
    void copyAndFix(char *output);
private:
    void make(Chunk *chunk);
};

#endif
