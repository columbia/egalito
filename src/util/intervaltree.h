#ifndef EGALITO_UTIL_INTERVAL_TREE_H
#define EGALITO_UTIL_INTERVAL_TREE_H

#include <vector>
#include <functional>
#include "range.h"

class IntervalTreeNode {
private:
    typedef std::vector<Range> RangeList;
private:
    Range totalRange;
    address_t midpoint;
    IntervalTreeNode *lower, *higher;
    RangeList overlapStart, overlapEnd;
private:
    IntervalTreeNode(const IntervalTreeNode &other) {}
public:
    IntervalTreeNode(Range totalRange) : totalRange(totalRange),
        midpoint((totalRange.getStart() + totalRange.getEnd()) / 2),
        lower(nullptr), higher(nullptr) {}
    IntervalTreeNode(IntervalTreeNode &&other) : totalRange(other.totalRange),
        midpoint(other.midpoint), lower(other.lower), higher(other.higher),
        overlapStart(std::move(other.overlapStart)),
        overlapEnd(std::move(overlapEnd))
        { other.lower = nullptr, other.higher = nullptr; }
    ~IntervalTreeNode();

    Range getTotalRange() const { return totalRange; }

    void add(Range range);
    void findOverlapping(address_t point, std::vector<Range> &found);
    bool findLowerBound(address_t point, Range *bound);
    bool findUpperBound(address_t point, Range *bound);
    Range upperBound(address_t point);

    void inStartOrderTraversal(std::function<void (Range)> callback);
};

class IntervalTree {
private:
    IntervalTreeNode *tree;
private:
    IntervalTree(const IntervalTree &other) {}
public:
    IntervalTree(Range totalRange) : tree(new IntervalTreeNode(totalRange)) {}
    IntervalTree(IntervalTree &&other) : tree(other.tree)
        { other.tree = nullptr; }
    ~IntervalTree();

    void add(Range range) { tree->add(range); }
    std::vector<Range> findOverlapping(address_t point);
    bool findLowerBound(address_t point, Range *lowerBound);
    bool findUpperBound(address_t point, Range *upperBound);
    IntervalTree complement();

    IntervalTreeNode *getRoot() const { return tree; }
};

#endif
