#include <cassert>
#include <algorithm>
#include "intervaltree.h"
#include "log/log.h"

IntervalTreeNode::~IntervalTreeNode() {
    delete lower;
    delete higher;
}

void IntervalTreeNode::add(Range range) {
    /*LOG(1, "adding " << range << " to " << totalRange
        << " with midpoint " << midpoint);*/
    assert(totalRange.contains(range));

    if(range < midpoint) {
        if(!lower) {
            lower = new IntervalTreeNode(
                Range::fromEndpoints(totalRange.getStart(), midpoint));
        }
        lower->add(range);
    }
    else if(range.contains(midpoint)) {
        overlapStart.push_back(range);
        std::sort(overlapStart.begin(), overlapStart.end());
        overlapEnd.push_back(range);
        std::sort(overlapEnd.begin(), overlapEnd.end(),
            [] (const Range &a, const Range &b) {
                if(b.getEnd() < a.getEnd()) return true;
                else if(b.getEnd() == a.getEnd()) {
                    if(b.getStart() < a.getStart()) return true;
                }
                return false;
            });
    }
    else {
        if(!higher) {
            higher = new IntervalTreeNode(
                Range::fromEndpoints(midpoint, totalRange.getEnd()));
        }
        higher->add(range);
    }
}

void IntervalTreeNode::findOverlapping(address_t point,
    std::vector<Range> &found) {

    if(point < midpoint) {
        if(lower) lower->findOverlapping(point, found);
        for(const auto &r : overlapStart) {
            if(r.contains(point)) found.push_back(r);
            if(point < r) break;
        }
    }
    if(point >= midpoint) {
        if(higher) higher->findOverlapping(point, found);
        for(const auto &r : overlapEnd) {
            if(r.contains(point)) found.push_back(r);
            if(r < point) break;
        }
    }
}

bool IntervalTreeNode::findLowerBound(address_t point, Range *bound) {
    if(point >= midpoint) {
        if(higher && higher->findLowerBound(point, bound)) return true;
    }

    for(RangeList::reverse_iterator it = overlapEnd.rbegin();
        it != overlapEnd.rend(); it ++) {

        Range r = *it;

        if(r < point) {
            *bound = r;
            return true;
        }
    }

    if(lower && lower->findLowerBound(point, bound)) return true;

    return false;
}

bool IntervalTreeNode::findUpperBound(address_t point, Range *bound) {
    if(point < midpoint) {
        if(lower && lower->findUpperBound(point, bound)) return true;
    }

    for(const auto &r : overlapStart) {
        if(point < r) {
            *bound = r;
            return true;
        }
    }

    if(higher && higher->findUpperBound(point, bound)) return true;

    return false;
}

void IntervalTreeNode::inStartOrderTraversal(std::function<void (Range)> callback) {
    if(lower) lower->inStartOrderTraversal(callback);

    for(const auto &r : overlapStart) {
        callback(r);
    }

    if(higher) higher->inStartOrderTraversal(callback);
}

IntervalTree::~IntervalTree() {
    delete tree;
}

std::vector<Range> IntervalTree::findOverlapping(address_t point) {
    std::vector<Range> found;
    tree->findOverlapping(point, found);
    return std::move(found);
}

bool IntervalTree::findLowerBound(address_t point, Range *lowerBound) {
    return tree->findLowerBound(point, lowerBound);
}

bool IntervalTree::findUpperBound(address_t point, Range *upperBound) {
    return tree->findUpperBound(point, upperBound);
}

IntervalTree IntervalTree::complement() {
    Range bounds = tree->getTotalRange();
    IntervalTree newTree(bounds);
    address_t lastPoint = bounds.getStart();

    tree->inStartOrderTraversal([&] (Range r) {
        address_t end = r.getStart();
        if(end > lastPoint) {
            newTree.add(Range::fromEndpoints(lastPoint, end));
        }

        lastPoint = std::max(lastPoint, r.getEnd());
    });

    if(lastPoint < bounds.getEnd()) {
        newTree.add(Range::fromEndpoints(lastPoint, bounds.getEnd()));
    }

    return std::move(newTree);
}
