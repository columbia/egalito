#include "generation.h"
#include "transform/sandbox.h"

void Generation::addChunk(Chunk *chunk) {
    auto slot = sandbox->allocate(chunk->getSize());
    chunk->writeTo(&slot);
}
