#ifndef EGALITO_POSITION_H
#define EGALITO_POSITION_H

#include "chunkref.h"
#include "types.h"

/** Represents the current address of a Chunk.
*/
class Position {
public:
    virtual ~Position() {}

    virtual address_t get() const = 0;
    virtual void set(address_t value) = 0;

    virtual void recalculate() {}
};

/** Stores an absolute address. Can be set later at runtime.

    Normally used for top-level Chunks like Functions.
*/
class AbsolutePosition : public Position {
private:
    address_t address;
public:
    AbsolutePosition(address_t address) : address(address) {}

    virtual address_t get() const { return address; }
    virtual void set(address_t value) { this->address = value; }
};

/** Stores an offset (usually 0) relative to another Chunk's position.

    The parent Chunk will be queried each time this Position is retrieved.
    This lack of caching makes this class useful for Chunks which are moved
    to new addresses frequently.
*/
class RelativePosition : public Position {
private:
    ChunkRef object;
    address_t offset;
public:
    // object should be the main object, offset is relative to the parent
    RelativePosition(ChunkRef object, address_t offset = 0)
        : object(object), offset(offset) {}

    virtual address_t get() const;
    virtual void set(address_t value);

    address_t getOffset() const { return offset; }
    void setOffset(address_t offset) { this->offset = offset; }
};

/** Represents a Chunk that immediately follows another.

    Like a RelativePosition with offset 0.
*/
class SubsequentPosition : public Position {
private:
    ChunkRef afterThis;
public:
    SubsequentPosition(ChunkRef afterThis) : afterThis(afterThis) {}

    virtual address_t get() const;
    virtual void set(address_t value);
};

/** Caches another Position type (useful for any computed type).

    The cached value must be updated whenever the parent Chunk is moved to a
    new address. These updates are done by ChunkMutator.
*/
template <typename PositionType>
class CachedPositionDecorator : public PositionType {
private:
    address_t cache;
public:
    CachedPositionDecorator(ChunkRef object)
        : PositionType(object) { recalculate(); }

    virtual address_t get() const { return cache; }
    virtual void set(address_t value) { PositionType::set(value); }

    virtual bool isCached() const { return true; }
    virtual void recalculate()
        { cache = PositionType::get(); }
};

typedef CachedPositionDecorator<SubsequentPosition> CachedSubsequentPosition;
typedef CachedPositionDecorator<RelativePosition> CachedRelativePosition;

class ComputedSize {
private:
    size_t size;
public:
    ComputedSize() : size(0) {}
    size_t get() const { return size; }
    void set(size_t newSize) { size = newSize; }
    void adjustBy(diff_t add);
};

class Range {
private:
    address_t _start;
    size_t _size;
public:
    Range(address_t start, size_t size) : _start(start), _size(size) {}

    address_t getStart() const { return _start; }
    address_t getEnd() const { return _start + _size; }
    size_t getSize() const { return _size; }

    bool contains(address_t point) const;
    bool contains(const Range &other) const;
    bool overlaps(address_t point) const;
    bool overlaps(const Range &other) const;

    bool operator < (const Range &other) const;
    bool operator == (const Range &other) const;

    static Range fromPoint(address_t point);
    static Range fromEndpoints(address_t start, address_t end);
};

#endif
