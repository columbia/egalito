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

    virtual bool isAuthority() const { return false; }
    virtual Chunk *findAuthority() const { return nullptr; }
    virtual void updateAuthority() {}

    virtual void recalculate() const {}
    virtual int getGeneration() const { return 0; }
    virtual void setGeneration(int gen) const {}
    virtual void incrementGeneration() const {}
protected:
    virtual Chunk *getDependency() const { return nullptr; }
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
    virtual void set(address_t value)
        { this->address = value; setGeneration(getGeneration() + 1); }

    virtual bool isAuthority() const { return true; }
};

/** Stores an offset relative to another Chunk's position.

    The parent Chunk will be queried each time this Position is retrieved.
    This lack of caching makes this class useful for Chunks which are moved
    to new addresses frequently.
*/
class OffsetPosition : public Position {
private:
    ChunkRef parent;
    address_t offset;
public:
    OffsetPosition(ChunkRef parent, address_t offset = 0)
        : parent(parent), offset(offset) {}

    virtual address_t get() const;
    virtual void set(address_t value);

    address_t getOffset() const { return offset; }
    void setOffset(address_t offset);
protected:
    virtual Chunk *getDependency() const { return &*parent; }
};

/** Represents a Chunk that immediately follows another.

    The afterThis Chunk can be the immediately prior sibling, or the
    Chunk immediately before this Chunk's parent, for instance.
*/
class SubsequentPosition : public Position {
private:
    ChunkRef afterThis;
public:
    SubsequentPosition(ChunkRef afterThis) : afterThis(afterThis) {}

    virtual address_t get() const;
    virtual void set(address_t value);
protected:
    virtual Chunk *getDependency() const { return &*afterThis; }
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

    virtual void recalculate()
        { cache = PositionType::get(); }
};

typedef CachedPositionDecorator<SubsequentPosition> CachedSubsequentPosition;
typedef CachedPositionDecorator<OffsetPosition> CachedOffsetPosition;

/** Decorator to allow generation tracking of any Position.
*/
template <typename PositionType>
class TrackedPositionDecorator : public PositionType {
private:
    mutable int generation;
public:
    TrackedPositionDecorator(ChunkRef chunk, int generation = 0)
        : PositionType(chunk), generation(generation) {}
    virtual int getGeneration() const { return generation; }
    virtual void setGeneration(int gen) const { generation = gen; }
    virtual void incrementGeneration() const { generation ++; }
};

// specialize for AbsolutePosition to add different constructor
template <>
class TrackedPositionDecorator<AbsolutePosition> : public AbsolutePosition {
private:
    mutable int generation;
public:
    TrackedPositionDecorator(address_t address, int generation = 0)
        : AbsolutePosition(address), generation(generation) {}
    virtual int getGeneration() const { return generation; }
    virtual void setGeneration(int gen) const { generation = gen; }
    virtual void incrementGeneration() const { generation ++; }
};

/** Tracks updates to positions with a generation counter.

    Each instance of this class stores an authority node and a generation.
    If the local generation does not match the authority's generation, then
    this position may need to be changed due to updates elsewhere in the
    Chunk hierarchy (and it will be recalculated). Any modification of this
    Chunk's position or size will increment the authority's generation.

    If the containing Chunk is inserted into another hierarchy or position
    types are changed (from AbsolutePosition to something else, etc), then
    the authority may be out-of-date and updateAuthority() must be called.
    Note that the old authority will continue to be used unless its
    generation has changed, so remove the Chunk from the old tree before
    inserting it into the new one.
*/
template <typename PositionType>
class GenerationalPositionDecorator : public PositionType {
private:
    ChunkRef authority;
    mutable address_t cache;
public:
    GenerationalPositionDecorator(ChunkRef chunk)
        : PositionType(chunk) { updateAuthority(); recalculate(); }

    virtual address_t get() const;
    virtual void set(address_t value);

    virtual void recalculate() const;

    virtual bool isAuthority() const { return false; }
    virtual Chunk *findAuthority() const;
    virtual void updateAuthority() { authority = findAuthority(); }

    using PositionType::getGeneration;
    using PositionType::setGeneration;
protected:
    using PositionType::getDependency;
private:
    int getAuthorityGeneration() const;
};

typedef GenerationalPositionDecorator<
    TrackedPositionDecorator<SubsequentPosition>>
        GenerationalSubsequentPosition;
typedef GenerationalPositionDecorator<
    TrackedPositionDecorator<OffsetPosition>>
        GenerationalOffsetPosition;

class PositionFactory {
public:
    enum Mode {
        MODE_GENERATION_OFFSET,
        MODE_GENERATION_SUBSEQUENT,
        MODE_CACHED_OFFSET,
        MODE_CACHED_SUBSEQUENT,
        MODE_OFFSET,
        MODE_SUBSEQUENT,

        MODE_FAST_UPDATES = MODE_GENERATION_OFFSET,
        MODE_FAST_RETRIEVAL = MODE_CACHED_OFFSET,
        MODE_LOWER_MEMORY = MODE_CACHED_SUBSEQUENT,
        MODE_DEBUGGING_NO_CACHE = MODE_SUBSEQUENT
    };
private:
    Mode mode;
public:
    PositionFactory(Mode mode) : mode(mode) {}
    Position *makeAbsolutePosition(address_t address);
    Position *makePosition(Chunk *previous, Chunk *parent, address_t offset);
    bool needsGenerationTracking() const;
    bool needsUpdatePasses() const;
private:
    template <typename PosType>
    PosType *setOffset(PosType *pos, address_t offset)
        { pos->setOffset(offset); return pos; }
};

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
