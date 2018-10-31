#include "chunk.h"
#include "chunk/position.h"
#include "log/log.h"

void ChunkImpl::setPosition(Position *newPosition) {
    throw "Operation not supported: ChunkImpl::setPosition"
        " (use ChunkSinglePositionDecorator)";
}

void ChunkImpl::setSize(size_t newSize) {
    throw "Operation not supported: ChunkImpl::setSize";
}

void ChunkImpl::addToSize(diff_t add) {
    throw "Operation not supported: ChunkImpl::addToSize";
}

address_t ChunkImpl::getAddress() const {
    //return getPosition()->get();
    return PositionManager::getAddress(this);
}

Range ChunkImpl::getRange() const {
    return std::move(Range(getAddress(), getSize()));
}
