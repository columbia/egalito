#include <cassert>
#include <utility>  // for std::move
#include "size.h"

void ComputedSize::adjustBy(diff_t add) {
    assert(static_cast<diff_t>(size + add) >= 0);
    size += add;
}

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
