#include <iomanip>
#include "mutator.h"
#include "position.h"
#include "pass/positiondump.h"
#include "log/log.h"

void ChunkMutator::makePositionFor(Chunk *child) {
    PositionFactory *positionFactory = PositionFactory::getInstance();
    Position *pos = nullptr;
    ChunkCursor cursor(chunk, child);
    ChunkCursor prev = cursor;
    if(prev.prev()) {
        pos = positionFactory->makePosition(
            prev.get(), child, prev.get()->getAddress() - chunk->getAddress());
    }
    else {
        pos = positionFactory->makePosition(chunk, child, 0);
    }
    child->setPosition(pos);
}

void ChunkMutator::prepend(Chunk *child) {
    if(chunk->getChildren()->genericGetSize() == 0) {
        append(child);
    }
    else {
        insertBefore(chunk->getChildren()->genericGetAt(0), child);
    }
}

void ChunkMutator::append(Chunk *child) {
    // set sibling pointers
    auto prev = chunk->getChildren()->genericGetLast();
    if(prev) {
        child->setPreviousSibling(prev);
        prev->setNextSibling(child);
    }
    else {
        child->setPreviousSibling(nullptr);
        child->setNextSibling(nullptr);
    }

    // set children and parent pointers
    chunk->getChildren()->genericAdd(child);
    child->setParent(chunk);

    if(!child->getPosition()) makePositionFor(child);
    updateSizesAndAuthorities(child);
}

void ChunkMutator::insertAfter(Chunk *insertPoint, Chunk *newChunk) {
    // set sibling pointers
    setPreviousSibling(newChunk, insertPoint);
    if(insertPoint) {
        setNextSibling(newChunk, insertPoint->getNextSibling());
        setNextSibling(insertPoint, newChunk);
    }
    else {
        newChunk->setNextSibling(nullptr);
    }

    // set children and parent pointers
    auto list = chunk->getChildren();
    size_t index = (insertPoint ? list->genericIndexOf(insertPoint) + 1 : 0);
    list->genericInsertAt(index, newChunk);
    newChunk->setParent(chunk);

    if(!newChunk->getPosition()) makePositionFor(newChunk);
    updateSizesAndAuthorities(newChunk);
}

void ChunkMutator::insertBefore(Chunk *insertPoint, Chunk *newChunk) {
    if(!insertPoint) {
        append(newChunk);
        return;
    }

    // set sibling pointers
    newChunk->setNextSibling(insertPoint);
    newChunk->setPreviousSibling(insertPoint->getPreviousSibling());
    insertPoint->setNextSibling(newChunk);

    // set children and parent pointers
    auto list = chunk->getChildren();
    size_t index = list->genericIndexOf(insertPoint);
    list->genericInsertAt(index, newChunk);
    newChunk->setParent(chunk);

    if(!newChunk->getPosition()) makePositionFor(newChunk);
    updateSizesAndAuthorities(newChunk);
}

void ChunkMutator::setPosition(address_t address) {
    chunk->getPosition()->set(address);
}

void ChunkMutator::updateSizesAndAuthorities(Chunk *child) {
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

void ChunkMutator::updatePositions() {
    if(!allowUpdates) return;
    if(!PositionFactory::getInstance()->needsUpdatePasses()) return;

    for(Chunk *c = chunk; c; c = c->getParent()) {
        if(dynamic_cast<AbsolutePosition *>(c->getPosition())) {
            updatePositionHelper(c);
            PositionDump().visit(c);
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

void ChunkMutator::setPreviousSibling(Chunk *c, Chunk *prev) {
    c->setPreviousSibling(prev);
    if(auto v = dynamic_cast<SubsequentPosition *>(c->getPosition())) {
        v->setAfterThis(prev);
    }
    else {
        fixOffsets();
    }
}

void ChunkMutator::setNextSibling(Chunk *c, Chunk *next) {
    c->setNextSibling(next);
    if(auto v = dynamic_cast<SubsequentPosition *>(next->getPosition())) {
        v->setAfterThis(c);
    }
    else {
        fixOffsets();
    }
}

void ChunkMutator::fixOffsets() {
    address_t offset = 0;
    for(auto other : chunk->getChildren()->genericIterable()) {
        if(auto p = dynamic_cast<OffsetPosition *>(other->getPosition())) {
            p->setOffset(offset);
            if(PositionFactory::getInstance()->needsGenerationTracking()) {
                p->incrementGeneration();
            }
        }
        offset += other->getSize();
    }
}
