#ifndef EGALITO_UTIL_RANGE_H
#define EGALITO_UTIL_RANGE_H

#include <iosfwd>
#include "types.h"

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

    bool operator < (address_t point) const;
    bool operator < (const Range &other) const;
    bool operator == (const Range &other) const;

    static Range fromPoint(address_t point);
    static Range fromEndpoints(address_t start, address_t end);
};

bool operator < (address_t point, const Range &range);
std::ostream &operator << (std::ostream &stream, const Range &range);

#endif
