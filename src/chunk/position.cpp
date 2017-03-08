#include <climits>  // for INT_MIN
#include <cassert>
#include <algorithm>  // for std::max
#include "position.h"
#include "chunk.h"
#include "chunklist.h"  // for getChildren()
#include "log/log.h"

address_t OffsetPosition::get() const {
    if(chunk == nullptr || chunk->getParent() == nullptr) return 0;
    return chunk->getParent()->getPosition()->get() + offset;
}

void OffsetPosition::set(address_t value) {
    assert(chunk != nullptr);
    assert(chunk->getParent() != nullptr);
    setOffset(value - chunk->getParent()->getPosition()->get());
}

void OffsetPosition::setOffset(address_t offset) {
    this->offset = offset;
}

void OffsetPosition::recalculate() {
    if(!chunk->getParent() || !chunk->getParent()->getChildren()) {
        offset = 0;
        return;
    }

    auto prev = chunk->getPreviousSibling();
    if(prev) {
        auto parent = chunk->getParent();
        offset = (prev->getPosition()->get() - parent->getPosition()->get())
            + prev->getSize();
    }
    else {
        offset = 0;
    }
}

Chunk *OffsetPosition::getDependency() const {
    return chunk->getParent();
}

address_t SubsequentPosition::get() const {
    return afterThis->getPosition()->get() + afterThis->getSize();
}

void SubsequentPosition::set(address_t value) {
    throw "Can't set position of a SubsequentPosition";
}

template class GenerationalPositionDecorator<
    TrackedPositionDecorator<SubsequentPosition>>;
template class GenerationalPositionDecorator<
    TrackedPositionDecorator<OffsetPosition>>;

template <typename PositionType>
address_t GenerationalPositionDecorator<PositionType>::get() const {
    if(authority && getGeneration() != getAuthorityGeneration()) {
        const_cast<GenerationalPositionDecorator<PositionType> *>(this)
            ->recalculate();
        setGeneration(getAuthorityGeneration());
    }
    return cache;
}

template <typename PositionType>
void GenerationalPositionDecorator<PositionType>::set(address_t value) {
    if(authority) {
        int g = std::max(
            getGeneration() + 1,
            getAuthorityGeneration() + 1);
        authority->getPosition()->setGeneration(g);
        setGeneration(g);
    }
    else {
        setGeneration(getGeneration() + 1);
    }
    this->cache = value;
    PositionType::set(value);
}

template <typename PositionType>
Chunk *GenerationalPositionDecorator<PositionType>::findAuthority() const {
    // A little bit tricky: use old authority if its generation is new enough.
    // This prevents O(n^2) calls when updating authorities of a whole basic
    // block at a time.
    if(authority && getGeneration() == getAuthorityGeneration()) {
        return &*authority;
    }

    if(getDependency()) {
        auto a = getDependency()->getPosition()->findAuthority();
        return a ? a : getDependency();
    }

    return nullptr;
}

template <typename PositionType>
int GenerationalPositionDecorator<PositionType>
    ::getAuthorityGeneration() const {

    return authority->getPosition()->getGeneration();
}

template <typename PositionType>
void GenerationalPositionDecorator<PositionType>::recalculate() {
    PositionType::recalculate();
    cache = PositionType::get();
}

PositionFactory *PositionFactory::instance;

Position *PositionFactory::makeAbsolutePosition(address_t address) {
    if(needsGenerationTracking()) {
        return new TrackedPositionDecorator<AbsolutePosition>(address);
    }
    else {
        return new AbsolutePosition(address);
    }
}

Position *PositionFactory::makePosition(Chunk *previous, Chunk *chunk,
    address_t offset) {

    if(!previous) {
        // e.g. first block in function
        if(needsGenerationTracking()) {
            return setOffset(new GenerationalOffsetPosition(chunk), offset);
        }
        else {
            return new OffsetPosition(chunk, offset);
        }
    }

    switch(mode) {
    case MODE_GENERATION_OFFSET:
        return setOffset(new GenerationalOffsetPosition(chunk), offset);
    case MODE_GENERATION_SUBSEQUENT:
        return new GenerationalSubsequentPosition(previous);
    case MODE_CACHED_OFFSET: {
        auto p = new CachedOffsetPosition(chunk);
        p->setOffset(offset);
        p->recalculate();
        return p;
    }
    case MODE_CACHED_SUBSEQUENT:
        return new CachedSubsequentPosition(previous);
    case MODE_OFFSET:
        return new OffsetPosition(chunk, offset);
    case MODE_SUBSEQUENT:
        return new SubsequentPosition(previous);
    default:
        throw "Unknown mode in PositionFactory";
    }
}

bool PositionFactory::needsGenerationTracking() const {
    return mode == MODE_GENERATION_OFFSET
        || mode == MODE_GENERATION_SUBSEQUENT;
}

bool PositionFactory::needsUpdatePasses() const {
    return mode == MODE_CACHED_OFFSET
        || mode == MODE_CACHED_SUBSEQUENT
        || mode == MODE_OFFSET;
}

bool PositionFactory::needsSpecialCaseFirst() const {
    return mode == MODE_SUBSEQUENT
        || mode == MODE_CACHED_SUBSEQUENT
        || mode == MODE_GENERATION_SUBSEQUENT;
}
