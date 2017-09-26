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
public:
    IntervalTreeNode(Range totalRange) : totalRange(totalRange),
        midpoint((totalRange.getStart() + totalRange.getEnd()) / 2),
        lower(nullptr), higher(nullptr) {}
    ~IntervalTreeNode();

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
public:
    IntervalTree(Range totalRange) : tree(new IntervalTreeNode(totalRange)) {}
    ~IntervalTree();

    void add(Range range) { tree->add(range); }
    std::vector<Range> findOverlapping(address_t point);
    bool findLowerBound(address_t point, Range *lowerBound);
    bool findUpperBound(address_t point, Range *upperBound);

    IntervalTreeNode *getRoot() const { return tree; }
};

#endif
