#ifndef EGALITO_CHUNK_SIZE_H
#define EGALITO_CHUNK_SIZE_H

#include "types.h"

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

    bool endsWith(address_t point) const;

    bool operator < (const Range &other) const;
    bool operator == (const Range &other) const;

    static Range fromPoint(address_t point);
    static Range fromEndpoints(address_t start, address_t end);
};

#endif
