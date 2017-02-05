#include "chunk.h"
#include "log/log.h"

void ChunkImpl::setSize(size_t newSize) {
    throw "Operation not supported: ChunkImpl::setSize";
}

void ChunkImpl::addToSize(diff_t add) {
    throw "Operation not supported: ChunkImpl::addToSize";
}

address_t ChunkImpl::getAddress() const {
    return getPosition()->get();
}

Range ChunkImpl::getRange() const {
    return std::move(Range(getAddress(), getSize()));
}
