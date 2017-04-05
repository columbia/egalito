#ifndef EGALITO_CHUNK_MUTATOR_H
#define EGALITO_CHUNK_MUTATOR_H

#include "chunk/chunk.h"
#include "chunk/chunklist.h"
#include "cursor.h"

/** Class to add/remove children in the Chunk hierarchy.

    Sizes are updated immediately whenever a child is added or removed,
    because only parents' sizes must be updated as a result. Position updates
    are delayed and applied by the destructor (can also be manually invoked),
    because this potentially requires updating many sibling positions.
*/
class ChunkMutator {
private:
    Chunk *chunk;
    bool allowUpdates;
public:
    ChunkMutator(Chunk *chunk, bool allowUpdates = true)
        : chunk(chunk), allowUpdates(allowUpdates) {}
    ~ChunkMutator() { updatePositions(); }

    void makePositionFor(Chunk *child);

    /** Adds a child Chunk at the beginning of the children. */
    void prepend(Chunk *child);

    /** Adds a child Chunk at the end of the list of children. */
    void append(Chunk *child);

    /** Adds a new child immediately after insertPoint.

        If insertPoint is NULL, the newChunk becomes the first child.
    */
    void insertAfter(Chunk *insertPoint, Chunk *newChunk);

    /** Adds a new child immediately before insertPoint.

        If insertPoint is NULL, the newChunk is appended to the end.
    */
    void insertBefore(Chunk *insertPoint, Chunk *newChunk);

    /** Sets the position of a Chunk, performs any necessary updates. */
    void setPosition(address_t address);

    /** Call this to propagate position changes if a child's size is modified.
    */
    void modifiedChildSize(Chunk *child, int added);

    /** Force positions to be updated, if using cached positions. */
    void updatePositions();
private:
    void updateSizesAndAuthorities(Chunk *child);
    void updateGenerationCounts(Chunk *child);
    void updateAuthorityHelper(Chunk *root);
    void updatePositionHelper(Chunk *root);
    void setPreviousSibling(Chunk *c, Chunk *prev);
    void setNextSibling(Chunk *c, Chunk *next);
};

#endif
