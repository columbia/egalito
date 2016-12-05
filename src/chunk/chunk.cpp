#include <iostream>  // for debugging
#include <sstream>
#include <cstring>  // for memcpy
#include <cassert>
#include "chunk.h"
#include "disassemble.h"
#include "transform/sandbox.h"
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
