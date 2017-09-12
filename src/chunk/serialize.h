#ifndef EGALITO_CHUNK_SERIALIZE_H
#define EGALITO_CHUNK_SERIALIZE_H

#include <string>

class Chunk;

class ChunkSerializer {
public:
    void serialize(Chunk *chunk, std::string filename);

    Chunk *deserialize(std::string filename);
};

#endif
