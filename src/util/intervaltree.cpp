#include <cassert>
#include <algorithm>
#include "intervaltree.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP chunk
#include "log/log.h"

IntervalTreeNode::~IntervalTreeNode() {
    delete lower;
    delete higher;
}

void IntervalTreeNode::add(Range range) {
    LOG(1, "adding [" << range.getStart() << ",+" << range.getSize() << ") to ["
        << totalRange.getStart() << ",+" << totalRange.getSize()
        << ") with midpoint " << midpoint);
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
    LOG(1, "    findLowerBound for " << point << " in " << totalRange);
    bool found = false;
    for(const auto &r : overlapEnd) {
    //for(RangeList::reverse_iterator it = overlapEnd.rbegin();
    //    it != overlapEnd.rend(); it ++) {
        //Range r = *it;

        LOG(1, "        " << r << " < " << point << " ?");
        if(r < point) {
            if(found && bound->getEnd() < r.getEnd()) {
                *bound = r;
            }
            //return true;
            found = true;
        }
    }

    if(point < midpoint) {
        if(lower) return lower->findLowerBound(point, bound);
    }
    if(point >= midpoint) {
        if(higher && higher->findLowerBound(point, bound)) return true;
    }

    //LOG(1, "findLowerBound: nope");
    return found;
}

bool IntervalTreeNode::findUpperBound(address_t point, Range *bound) {
    Range best(0, 0);
    bool foundBest = false;
    for(RangeList::reverse_iterator it = overlapStart.rbegin();
        it != overlapStart.rend(); it ++) {

        if(point < *it) {
            best = *it;
            foundBest = true;
        }
        else break;
    }
    if(foundBest) {
        *bound = best;
        return true;
    }

    if(point < midpoint) {
        if(lower) return lower->findUpperBound(point, bound);
    }
    if(point >= midpoint) {
        if(higher) return higher->findUpperBound(point, bound);
    }

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
    LOG(1, "findLowerBound for " << point);
    return tree->findLowerBound(point, lowerBound);
}

bool IntervalTree::findUpperBound(address_t point, Range *upperBound) {
    return tree->findUpperBound(point, upperBound);
}
