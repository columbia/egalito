#ifndef EGALITO_OPERATION_CURSOR_H
#define EGALITO_OPERATION_CURSOR_H

#include "types.h"

class ChunkList;
class Chunk;

class ChunkCursor {
private:
    ChunkList *list;
    size_t index;
public:
    ChunkCursor(Chunk *parent, size_t index);
    ChunkCursor(Chunk *chunk);
    ChunkCursor(Chunk *parent, Chunk *chunk);

    Chunk *get() const;
    size_t getIndex() const { return index; }

    bool prev();
    bool next();
    bool isEnd() const;

    static ChunkCursor makeBegin(Chunk *parent);
    static ChunkCursor makeEnd(Chunk *parent);
};

#endif
