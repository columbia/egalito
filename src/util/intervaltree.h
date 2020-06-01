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
        midpoint(totalRange.getStart() + (totalRange.getSize()/2)),
        lower(nullptr), higher(nullptr) {}
    IntervalTreeNode(IntervalTreeNode &&other) : totalRange(other.totalRange),
        midpoint(other.midpoint), lower(other.lower), higher(other.higher),
        overlapStart(std::move(other.overlapStart)),
        overlapEnd(std::move(other.overlapEnd))
        { other.lower = nullptr, other.higher = nullptr; }
    ~IntervalTreeNode();

    Range getTotalRange() const { return totalRange; }

    bool add(Range range);
    bool remove(Range range);
    void findOverlapping(address_t point, std::vector<Range> &found);
    void findOverlapping(Range range, std::vector<Range> &found);
    bool findLowerBound(address_t point, Range *bound);
    bool findLowerBoundOrOverlapping(address_t point, Range *bound);
    bool findUpperBound(address_t point, Range *bound);
    bool findUpperBoundOrOverlapping(address_t point, Range *bound);
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

    bool add(Range range) { return tree->add(range); }
    bool remove(Range range) { return tree->remove(range); }
    bool splitAt(address_t point);
    std::vector<Range> findOverlapping(address_t point);
    std::vector<Range> findOverlapping(Range range);
    bool findLowerBound(address_t point, Range *lowerBound);
    bool findLowerBoundOrOverlapping(address_t point, Range *lowerBound);
    bool findUpperBound(address_t point, Range *upperBound);
    bool findUpperBoundOrOverlapping(address_t point, Range *upperBound);
    void subtract(Range range);
    void subtractWithAddendum(Range range, Range addendum);
    IntervalTree complement();
    void unionWith(IntervalTree &otherTree);

    IntervalTreeNode *getRoot() const { return tree; }
    std::vector<Range> getAllData() const;

    void dump() const;
};

#endif
