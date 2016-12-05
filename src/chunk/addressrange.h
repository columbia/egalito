#ifndef EGALITO_CHUNK_ADDRESSRANGE_H
#define EGALITO_CHUNK_ADDRESSRANGE_H

#include <vector>
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

    bool overlaps(address_t point) const;
    bool overlaps(const Range &other) const;
};

class Chunk;

class RangeList {
private:
    class RangeNode {
    public:
        typedef std::pair<Range, Chunk *> ValueType;
    private:
        std::vector<ValueType> valueList;
        address_t lowerBound, upperBound;
        RangeNode *left, *right;
    private:
        static const size_t MAX_COUNT = 16;
    public:
        RangeNode() : RangeNode(0, 0) {}
        RangeNode(address_t lower, address_t upper)
            : lowerBound(lower), upperBound(upper),
            left(nullptr), right(nullptr) {}
        ~RangeNode();

        void insert(const Range &range, Chunk *value);
        bool wouldExpandFor(const Range &range) const;
        void split();

        bool boundsOverlapWith(address_t point) const;
        bool boundsOverlapWith(const Range &other) const;
        ValueType *findOverlapping(address_t point);
        ValueType *findOverlapping(const Range &other);
    };
private:
    RangeNode *root;
public:
    RangeList() : root(nullptr) {}
    ~RangeList();

    void insert(const Range &range, Chunk *value);
    RangeNode::ValueType *overlapping(address_t point);
    RangeNode::ValueType *overlapping(const Range &other);
};

#endif
