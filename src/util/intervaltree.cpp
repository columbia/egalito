#include <cassert>
#include <algorithm>
#include "intervaltree.h"
#include "log/log.h"

IntervalTreeNode::~IntervalTreeNode() {
    delete lower;
    delete higher;
}

bool IntervalTreeNode::add(Range range) {
    if(!totalRange.contains(range)) return false;

    /*LOG(1, "adding " << range << " to " << totalRange
        << " with midpoint " << midpoint);*/

    if(range < midpoint) {
        if(!lower) {
            lower = new IntervalTreeNode(
                Range::fromEndpoints(totalRange.getStart(), midpoint));
        }
        return lower->add(range);
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
        return higher->add(range);
    }

    return true;
}

bool IntervalTreeNode::remove(Range range) {
    if(range < midpoint) {
        if(lower) return lower->remove(range);
    }
    else if(midpoint < range) {
        if(higher) return higher->remove(range);
    }
    else {
        bool removed1 = false;
        bool removed2 = false;

        auto it1 = std::find(overlapStart.begin(), overlapStart.end(), range);
        if(it1 != overlapStart.end()) {
            overlapStart.erase(it1);
            removed1 = true;
        }

        auto it2 = std::find(overlapEnd.begin(), overlapEnd.end(), range);
        if(it2 != overlapEnd.end()) {
            overlapEnd.erase(it2);
            removed2 = true;
        }

        assert((removed1 && removed2) || (!removed1 && !removed2));
        return removed1 && removed2;
    }

    return false;
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
        for(const auto &r : overlapEnd) {
            if(r.contains(point)) found.push_back(r);
            if(r < point) break;
        }
        if(higher) higher->findOverlapping(point, found);
    }
}

void IntervalTreeNode::findOverlapping(Range range, std::vector<Range> &found) {
    bool searchLower = true, searchHigher = true;

    if(range < midpoint) searchHigher = false;
    if(midpoint < range || midpoint == range.getStart()) searchLower = false;

    if(searchLower && lower) {
        lower->findOverlapping(range, found);
    }

    // !!! inefficient compared to the above
    for(const auto &r : overlapStart) {
        if(r.overlaps(range)) found.push_back(r);
    }

    if(searchHigher && higher) {
        higher->findOverlapping(range, found);
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

bool IntervalTreeNode::findLowerBoundOrOverlapping(address_t point, Range *bound) {
    if(point >= midpoint) {
        if(higher && higher->findLowerBoundOrOverlapping(point, bound)) return true;
    }

    for(RangeList::reverse_iterator it = overlapEnd.rbegin();
        it != overlapEnd.rend(); it ++) {

        Range r = *it;

        if(r < point || r.contains(point)) {
            *bound = r;
            return true;
        }
    }

    if(lower && lower->findLowerBoundOrOverlapping(point, bound)) return true;

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

bool IntervalTree::splitAt(address_t point) {
    if(!tree->getTotalRange().contains(point)) return false;

    std::vector<Range> found = findOverlapping(point);

    if(found.size() == 1) {
        auto r = found[0];
        if(point != r.getStart() && point != r.getEnd()) {
            remove(found[0]);
            add(Range::fromEndpoints(r.getStart(), point));
            add(Range::fromEndpoints(point, r.getEnd()));
        }

        return true;
    }

    return false;
}

std::vector<Range> IntervalTree::findOverlapping(address_t point) {
    std::vector<Range> found;
    tree->findOverlapping(point, found);
    return std::move(found);
}

std::vector<Range> IntervalTree::findOverlapping(Range range) {
    std::vector<Range> found;
    tree->findOverlapping(range, found);
    return std::move(found);
}

bool IntervalTree::findLowerBound(address_t point, Range *lowerBound) {
    return tree->findLowerBound(point, lowerBound);
}

bool IntervalTree::findLowerBoundOrOverlapping(address_t point,
    Range *lowerBound) {

    return tree->findLowerBoundOrOverlapping(point, lowerBound);
}

bool IntervalTree::findUpperBound(address_t point, Range *upperBound) {
    return tree->findUpperBound(point, upperBound);
}

void IntervalTree::subtract(Range range) {
    std::vector<Range> overlapping = findOverlapping(range);

    for(Range r : overlapping) {
        remove(r);
        if(r.getStart() < range.getStart()) {
            add(Range::fromEndpoints(r.getStart(), range.getStart()));
        }
        if(range.getEnd() < r.getEnd()) {
            add(Range::fromEndpoints(range.getEnd(), r.getEnd()));
        }
    }
}

void IntervalTree::subtractWithAddendum(Range range, Range addendum) {
    std::vector<Range> overlapping = findOverlapping(range);

    for(Range r : overlapping) {
        remove(r);
        if(r.getStart() < range.getStart()) {
            add(Range::fromEndpoints(r.getStart(), range.getStart()));
        }
        if(addendum.getEnd() < r.getEnd()) {
            add(Range::fromEndpoints(addendum.getEnd(), r.getEnd()));
        }
    }
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

void IntervalTree::unionWith(IntervalTree &otherTree) {
    otherTree.getRoot()->inStartOrderTraversal([&] (Range range) {
        add(range);
    });
}

std::vector<Range> IntervalTree::getAllData() const {
    std::vector<Range> output;
    tree->inStartOrderTraversal([&] (const Range &r) {
        output.push_back(r);
    });
    return std::move(output);
}
