#ifndef EGALITO_CHUNK_MUTATOR_H
#define EGALITO_CHUNK_MUTATOR_H

#include "chunk.h"
#include "chunklist.h"

/** Class to add/remove children in the Chunk hierarchy.

    Sizes are updated immediately whenever a child is added or removed,
    because only parents' sizes must be updated as a result. Position updates
    are delayed and applied by the destructor (can also be manually invoked),
    because this potentially requires updating many sibling positions.
*/
class ChunkMutator {
private:
    Chunk *chunk;
public:
    ChunkMutator(Chunk *chunk) : chunk(chunk) {}
    ~ChunkMutator() { updatePositions(); }

    void append(Chunk *child);
    void setPosition(address_t address);

    void updatePositions();
private:
    void updatePositionHelper(Chunk *root);
};

#endif
