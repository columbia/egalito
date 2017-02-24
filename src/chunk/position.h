#ifndef EGALITO_POSITION_H
#define EGALITO_POSITION_H

#include "chunkref.h"
#include "types.h"

class Position {
public:
    virtual ~Position() {}

    virtual address_t get() const = 0;
    virtual void set(address_t value) = 0;
};

class AbsolutePosition : public Position {
private:
    address_t address;
public:
    AbsolutePosition(address_t address) : address(address) {}

    virtual address_t get() const { return address; }
    virtual void set(address_t value) { this->address = value; }
};

class RelativePosition : public Position {
private:
    ChunkRef object;
    address_t offset;
public:
    RelativePosition(ChunkRef object, address_t offset = 0)
        : object(object), offset(offset) {}

    virtual address_t get() const;
    virtual void set(address_t value);

    address_t getOffset() const { return offset; }
    void setOffset(address_t offset) { this->offset = offset; }
};

class SubsequentPosition : public Position {
private:
    ChunkRef following;
public:
    SubsequentPosition(ChunkRef following) : following(following) {}

    virtual address_t get() const;
    virtual void set(address_t value);
};

template <typename Type, int InvalidInitializer = -1>
class ValueCache {
public:
    static const Type INVALID = static_cast<Type>(InvalidInitializer);
private:
    Type cache;
public:
    ValueCache() : cache(INVALID) {}

    Type get() const { return cache; }
    void set(Type value) { cache = value; }

    void invalidate() { cache = INVALID; }
    bool isValid() const { return cache != INVALID; }
};

class CachedRelativePosition : protected RelativePosition {
private:
    mutable ValueCache<address_t> cache;
public:
    CachedRelativePosition(ChunkRef object) : RelativePosition(object) {}

    virtual address_t get() const;
    virtual void set(address_t value);

    using RelativePosition::getOffset;
    void setOffset(address_t offset);

    void invalidateCache() { cache.invalidate(); }
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
