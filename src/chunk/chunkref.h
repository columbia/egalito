#ifndef EGALITO_CHUNK_CHUNKREF_H
#define EGALITO_CHUNK_CHUNKREF_H

class Chunk;  // forward declaration

class ChunkRef {
private:
    Chunk *ref;
public:
    ChunkRef(Chunk *ref = nullptr) : ref(ref) {}

    Chunk &operator * () const { return *ref; }
    operator bool() const { return ref != nullptr; }
};

#endif
