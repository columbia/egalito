#include <cassert>
#include "cursor.h"
#include "chunk/chunk.h"
#include "chunk/chunklist.h"

ChunkCursor::ChunkCursor(Chunk *parent, size_t index)
    : list(parent->getChildren()), index(index) {

}

ChunkCursor::ChunkCursor(Chunk *chunk) {
    assert(chunk != nullptr);
    list = chunk->getParent()->getChildren();
    assert(list != nullptr);
    index = list->genericIndexOf(chunk);
}

ChunkCursor::ChunkCursor(Chunk *parent, Chunk *chunk)
    : list(parent->getChildren()) {

    assert(list != nullptr);
    index = list->genericIndexOf(chunk);
    assert(index != static_cast<size_t>(-1));
}

Chunk *ChunkCursor::get() const {
    return (index < list->genericGetSize()
        ? list->genericGetAt(index) : nullptr);
}

bool ChunkCursor::prev() {
    if(index > 0) {
        index --;
        return true;
    }
    return false;
}

bool ChunkCursor::next() {
    if(index < list->genericGetSize()) {
        index ++;
        return index < list->genericGetSize();
    }
    return false;
}

bool ChunkCursor::isEnd() const {
    return (index >= list->genericGetSize());
}

ChunkCursor ChunkCursor::makeBegin(Chunk *parent) {
    return ChunkCursor(parent, static_cast<size_t>(0));
}
ChunkCursor ChunkCursor::makeEnd(Chunk *parent) {
    return ChunkCursor(parent,
        parent->getChildren()->genericGetSize());
}

Chunk *ChunkCursor::getPrevious(Chunk *chunk) {
    ChunkCursor cursor(chunk);
    if(!cursor.prev()) return nullptr;
    return cursor.get();
}

Chunk *ChunkCursor::getNext(Chunk *chunk) {
    ChunkCursor cursor(chunk);
    if(!cursor.next()) return nullptr;
    return cursor.get();
}
