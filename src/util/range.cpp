#include <iostream>
#include <iomanip>
#include <cassert>
#include <utility>  // for std::move
#include "range.h"

bool Range::contains(address_t point) const {
    return point >= _start && point < getEnd();
}
bool Range::contains(const Range &other) const {
    return other._start >= _start && other.getEnd() <= getEnd();
}
bool Range::overlaps(address_t point) const {
    return contains(point);
}
bool Range::overlaps(const Range &other) const {
    return !(other._start >= getEnd() || other.getEnd() <= _start);
}

bool Range::endsWith(address_t point) const {
    return getEnd() == point;
}

bool Range::operator < (address_t point) const {
    return _start + _size <= point;
}
bool Range::operator < (const Range &other) const {
    if(_start < other._start) return true;
    if(_start == other._start) {
        if(getEnd() < other.getEnd()) return true;
    }

    return false;
}
bool Range::operator == (const Range &other) const {
    return _start == other._start && _size == other._size;
}

Range Range::fromPoint(address_t point) {
    return std::move(Range(point, 1));
}
Range Range::fromEndpoints(address_t start, address_t end) {
    assert(end >= start);
    return std::move(Range(start, end - start));
}

bool operator < (address_t point, const Range &range) {
    return point < range.getStart();
}

std::ostream &operator << (std::ostream &stream, const Range &range) {
    stream << "[0x" << std::hex << range.getStart()
        << ",+" << std::dec << range.getSize() << ")";
    return stream;
}
