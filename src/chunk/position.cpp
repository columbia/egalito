#include <climits>  // for INT_MIN
#include <cassert>
#include "position.h"
#include "chunk.h"

address_t RelativePosition::get() const {
    assert(object != nullptr);
    assert(object->getParent() != nullptr);
    return object->getParent()->getPosition()->get() + offset;
}

void RelativePosition::set(address_t value) {
    assert(object != nullptr);
    assert(object->getParent() != nullptr);
    assert(value >= object->getParent()->getPosition()->get());
    setOffset(value - object->getParent()->getPosition()->get());
}

address_t SubsequentPosition::get() const {
    return afterThis->getPosition()->get() + afterThis->getSize();
}

void SubsequentPosition::set(address_t value) {
    throw "Can't set position of a SubsequentPosition";
}

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
