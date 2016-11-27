#ifndef EGALITO_CHUNK_CHUNKREF_H
#define EGALITO_CHUNK_CHUNKREF_H

class Chunk;  // forward declaration

class ChunkRef {
private:
    Chunk *ref;
public:
    ChunkRef(Chunk *ref = nullptr) : ref(ref) {}

    Chunk &operator * () const { return *ref; }
    Chunk *operator -> () const { return ref; }
    operator bool() const { return ref != nullptr; }

    bool operator == (Chunk *other) const { return ref == other; }
    bool operator == (const ChunkRef &other) const { return ref == other.ref; }
    bool operator != (Chunk *other) const { return ref != other; }
    bool operator != (const ChunkRef &other) const { return ref != other.ref; }
};

#endif
