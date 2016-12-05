#include <utility>  // for std::make_pair
#include "addressrange.h"

bool Range::overlaps(address_t point) const {
    return point >= _start && point < _start + _size;
}

bool Range::overlaps(const Range &other) const {
    return !(other._start >= getEnd() || other.getEnd() <= _start);
}

RangeList::RangeNode::~RangeNode() {
    if(left) delete left;
    if(right) delete right;
}

void RangeList::RangeNode::insert(const Range &range, Chunk *value) {
    if(valueList.size() >= MAX_COUNT) split();

    if(left && right) {
        bool goLeft = !left->wouldExpandFor(range);
        bool goRight = !right->wouldExpandFor(range);

        if(!goLeft && !goRight) {
            if(range.getEnd() > right->upperBound) goRight = true;
            else goLeft = true;
        }

        if(goLeft) left->insert(range, value);
        if(goRight) right->insert(range, value);
    }
    else {
        if(range.getStart() < lowerBound) lowerBound = range.getStart();
        if(range.getEnd() > upperBound) upperBound = range.getEnd();

        valueList.push_back(std::make_pair(range, value));
    }
}

bool RangeList::RangeNode::wouldExpandFor(const Range &range) const {
    return range.getStart() < lowerBound || range.getEnd() > upperBound;
}

void RangeList::RangeNode::split() {
    if(left && right) return;

    address_t middle = (lowerBound + upperBound) / 2;
    left = new RangeNode(lowerBound, middle);
    right = new RangeNode(middle, upperBound);

    for(auto r : valueList) {
        if(r.first.getStart() < middle) left->insert(r.first, r.second);
        else right->insert(r.first, r.second);
    }
}

bool RangeList::RangeNode::boundsOverlapWith(address_t point) const {
    return point >= lowerBound && point < upperBound;
}

bool RangeList::RangeNode::boundsOverlapWith(const Range &other) const {
    return !(other.getEnd() <= lowerBound
        || other.getStart() >= upperBound);
}

RangeList::RangeNode::ValueType *RangeList::RangeNode::findOverlapping(address_t point) {
    if(left && right) {
        if(left->boundsOverlapWith(point)) {
            if(auto r = left->findOverlapping(point)) return r;
        }
        if(right->boundsOverlapWith(point)) {
            if(auto r = right->findOverlapping(point)) return r;
        }
    }
    else {
        for(auto &r : valueList) {
            if(r.first.overlaps(point)) return &r;
        }
    }
    return nullptr;
}

RangeList::RangeNode::ValueType *RangeList::RangeNode::findOverlapping(const Range &other) {
    if(left && right) {
        if(left->boundsOverlapWith(other)) {
            if(auto r = left->findOverlapping(other)) return r;
        }
        if(right->boundsOverlapWith(other)) {
            if(auto r = right->findOverlapping(other)) return r;
        }
    }
    else {
        for(auto &r : valueList) {
            if(r.first.overlaps(other)) return &r;
        }
    }
    return nullptr;
}

RangeList::~RangeList() {
    if(root) delete root;
}

void RangeList::insert(const Range &range, Chunk *value) {
    if(!root) root = new RangeNode();

    root->insert(range, value);
}

RangeList::RangeNode::ValueType *RangeList::overlapping(address_t point) {
    return root ? root->findOverlapping(point) : nullptr;
}

RangeList::RangeNode::ValueType *RangeList::overlapping(const Range &other) {
    return root ? root->findOverlapping(other) : nullptr;
}
