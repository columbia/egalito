#include "mutator.h"

void ChunkMutator::append(Chunk *child) {
    chunk->getChildren()->genericAdd(child);
    child->setParent(chunk);
    for(Chunk *p = chunk; p; p = p->getParent()) {
        p->addToSize(child->getSize());
    }
}

#if 0
void ChunkMutator::updatePositions() {
    for(Chunk *c = chunk; c; c = c->getParent()) {
        if(dynamic_cast<AbsolutePosition *>(c->getPosition())) {
            updatePositionHelper(c);
        }
    }
}

void ChunkMutator::updatePositionHelper(Chunk *root) {
    if(root->getChildren()) {
        for(auto child : root->getChildren()->genericIterable()) {
            updatePositionHelper(child);
        }
    }

    root->getPosition()->recalculate();
}
#endif
