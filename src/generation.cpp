#include "generation.h"

void Generation::addChunk(Chunk *chunk) {
    auto slot = sandbox->allocate(chunk->getSize());
    chunk->writeTo(slot);
}
