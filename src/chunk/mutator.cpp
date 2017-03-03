#include <iomanip>
#include "mutator.h"
#include "pass/positiondump.h"
#include "log/log.h"

void ChunkMutator::append(Chunk *child) {
    // set sibling pointers
    auto prev = chunk->getChildren()->genericGetLast();
    if(prev) {
        child->setPreviousSibling(prev);
        prev->setNextSibling(child);
    }

    // set children and parent pointers
    chunk->getChildren()->genericAdd(child);
    child->setParent(chunk);

    // update sizes of parents and grandparents
    for(Chunk *c = chunk; c; c = c->getParent()) {
        c->addToSize(child->getSize());
    }

    // update authority pointers in positions
    if(PositionFactory::getInstance()->needsGenerationTracking()) {
        //child->getPosition()->updateAuthority();
        chunk->getPosition()->incrementGeneration();
        chunk->getPosition()->incrementGeneration();
        child->getPosition()->incrementGeneration();
        updateAuthorityHelper(child);
    }
}

void ChunkMutator::setPosition(address_t address) {
    chunk->getPosition()->set(address);
}

void ChunkMutator::updatePositions() {
    if(!allowUpdates) return;
    if(!PositionFactory::getInstance()->needsUpdatePasses()) return;

    for(Chunk *c = chunk; c; c = c->getParent()) {
        if(dynamic_cast<AbsolutePosition *>(c->getPosition())) {
            updatePositionHelper(c);
            //PositionDump().visit(c);
        }
    }
}

void ChunkMutator::updateAuthorityHelper(Chunk *root) {
    root->getPosition()->updateAuthority();

    if(root->getChildren()) {
        for(auto child : root->getChildren()->genericIterable()) {
            updateAuthorityHelper(child);
        }
    }
}

void ChunkMutator::updatePositionHelper(Chunk *root) {
    // Must recalculate root's position before descending into children,
    // since some Position types depend on parents.
    root->getPosition()->recalculate();

    if(root->getChildren()) {
        for(auto child : root->getChildren()->genericIterable()) {
            updatePositionHelper(child);
        }
    }
}
