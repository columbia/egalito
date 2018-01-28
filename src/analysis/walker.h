#ifndef EGALITO_ANALYSIS_WALKER_H
#define EGALITO_ANALYSIS_WALKER_H

#include <vector>
#include <algorithm>
#include "analysis/graph.h"
#include "util/iter.h"

template <typename DerivedType>
class DFSWalkerBase {
private:
    GraphBase *graph;
    std::vector<bool> visited;

protected:
    DFSWalkerBase(GraphBase *graph) : graph(graph) {}
    void walk(int id, int dir) {
        visited.assign(graph->getCount(), false);
        reset();
        walkHelper(id, dir);
        finish();
    }

    void walkAll(int id, int dir) {
        visited.assign(graph->getCount(), false);
        reset();
        walkHelper(id, dir);
        for(size_t i = 1; i < graph->getCount(); i++) {
            if(!visited[i]) {
                tick();
                walkHelper(i, dir);
            }
        }
        finish();
    }

private:
    void walkHelper(int id, int dir) {
        visited[id] = true;
        preVisit(graph->get(id));
        for(auto link : graph->get(id)->getLinks(dir)) {
            auto n = link->getTargetID();
            if(!visited[n]) {
                walkHelper(link->getTargetID(), dir);
            }
            else {
                lateVisit(graph->get(id), &*link);
            }
        }
        postVisit(graph->get(id));
    };

    DerivedType &derived() {
        return *static_cast<DerivedType *>(this);
    }

    void reset() { derived().reset(); }
    void tick() { derived().tick(); }
    void finish() { derived().finish(); }
    void preVisit(GraphNodeBase *node) { derived().preVisit(node); }
    void postVisit(GraphNodeBase *node) { derived().postVisit(node); }
    void lateVisit(GraphNodeBase *from, GraphLinkBase *link)
        { derived().lateVisit(from, link); }
};

class PreorderVisitor {
public:
    void preVisit(std::vector<int> *order, int id) { order->push_back(id); }
    void postVisit(std::vector<int> *oder, int id) {}
};

class PostorderVisitor {
public:
    void preVisit(std::vector<int> *oder, int id) {}
    void postVisit(std::vector<int> *order, int id) { order->push_back(id); }
};

class PrePostorderVisitor {
public:
    void preVisit(std::vector<int> *order, int id) { order->push_back(id); }
    void postVisit(std::vector<int> *order, int id) { order->push_back(id); }
};

class EmptyFinisher {
public:
    template <typename ListType>
    void finish(ListType *order) {}
};

class ReverseFinisher {
public:
    template <typename ListType>
    void finish(ListType *order)
        { std::reverse(order->begin(), order->end()); }
};

template <int Direction, typename VisitType, typename FinishType>
class NodeCollection {
private:
    std::vector<std::vector<int>> order;
    int lap;
public:
    NodeCollection(GraphBase *graph)
        : order(graph->getCount()), lap(0) {}

    const std::vector<std::vector<int>>& get() const { return order; }

    void reset() {
        lap = 0;
        order.clear();
        order.push_back(std::vector<int>());
    }
    void tick() {
        lap++;
        order.push_back(std::vector<int>());
    }
    void preVisit(GraphNodeBase *node) {
        VisitType().preVisit(&order[lap], node->getID());
    }
    void postVisit(GraphNodeBase *node) {
        VisitType().postVisit(&order[lap], node->getID());
    }
    void lateVisit(GraphNodeBase *from, GraphLinkBase *link) { }
    void finish() {
        for(auto& o : order) {
            FinishType().finish(&o);
        }
    }
};

template <int Direction, typename VisitType, typename FinishType>
class SccCollection {
private:
    GraphBase *graph;
    int scc;
    int disc;
    std::vector<int> discovery;
    std::vector<int> lowLink;
    std::vector<bool> onStack;
    std::vector<int> stack;
    std::vector<int> poStack;
    std::vector<std::vector<int>> sccOrder;

public:
    SccCollection(GraphBase *graph)
        : graph(graph), scc(0), disc(0),
          discovery(graph->getCount()), lowLink(graph->getCount()),
          onStack(graph->getCount()) {}

    const std::vector<std::vector<int>>& get() const { return sccOrder; }

    void reset() {
        scc = 0;
        disc = 0;
        sccOrder.clear();
        sccOrder.push_back(std::vector<int>());
    }
    void tick() {}
    void preVisit(GraphNodeBase *node) {
        discovery[node->getID()] = disc;
        lowLink[node->getID()] = disc;
        stack.push_back(node->getID());
        onStack[node->getID()] = true;
        ++disc;
    }
    void postVisit(GraphNodeBase *node) {
        for(auto link : node->getLinks(Direction)) {
            if(discovery[node->getID()] < discovery[link->getTargetID()]) {
                lowLink[node->getID()] = std::min(lowLink[node->getID()],
                                                  lowLink[link->getTargetID()]);
            }
        }
        poStack.push_back(node->getID());
        if(discovery[node->getID()] == lowLink[node->getID()]) {
            auto it = stack.end();
            auto poit = poStack.end();
            do{
                --it;
                --poit;
                onStack[*it] = false;
            }while(*it != node->getID());
            stack.erase(it, stack.end());
            sccOrder[scc].insert(sccOrder[scc].end(), poit, poStack.end());
            poStack.erase(poit, poStack.end());
            FinishType().finish(&sccOrder[scc]);
            ++scc;
            sccOrder.push_back(std::vector<int>());
        }
    }
    void lateVisit(GraphNodeBase *from, GraphLinkBase *link) {
        if(onStack[link->getTargetID()]) {
            lowLink[from->getID()] = std::min(lowLink[from->getID()],
                                              discovery[link->getTargetID()]);
        }
    }
    void finish() {
        sccOrder.pop_back();
        FinishType().finish(&sccOrder);
    }
};

template <
    int Direction,
    typename VisitType,
    typename FinishType,
    template <int, typename, typename> class CollectType
>
class OrderOnCFG
    : DFSWalkerBase<OrderOnCFG<Direction, VisitType, FinishType, CollectType>> {

    friend class DFSWalkerBase<
        OrderOnCFG<Direction, VisitType, FinishType, CollectType>>;

private:
    CollectType<Direction, VisitType, FinishType> collector;

    typedef DFSWalkerBase<
        OrderOnCFG<Direction, VisitType, FinishType, CollectType>> BaseType;

public:
    OrderOnCFG(GraphBase *graph)
        : BaseType(graph), collector(graph) {}

    void gen(int id) { BaseType::walk(id, Direction); }
    void genFull(int id) { BaseType::walkAll(id, Direction); }

    const std::vector<std::vector<int>>& get() const
        { return collector.get(); }

private:
    void reset() { collector.reset(); }
    void tick() { collector.tick(); }
    void preVisit(GraphNodeBase *node) { collector.preVisit(node); }
    void postVisit(GraphNodeBase *node) { collector.postVisit(node); }
    void lateVisit(GraphNodeBase *from, GraphLinkBase *link)
        { collector.lateVisit(from, link); }
    void finish() { collector.finish(); }
};

typedef OrderOnCFG<
    1, PreorderVisitor, EmptyFinisher, NodeCollection
> Preorder;

typedef OrderOnCFG<
    1, PostorderVisitor, EmptyFinisher, NodeCollection
> Postorder;

typedef OrderOnCFG<
    1, PostorderVisitor, ReverseFinisher, NodeCollection
> ReversePostorder;

typedef OrderOnCFG<
    -1, PostorderVisitor, ReverseFinisher, NodeCollection
> ReverseReversePostorder;

typedef OrderOnCFG<
    1, PostorderVisitor, ReverseFinisher, SccCollection
> SccOrder;

typedef OrderOnCFG<
    -1, PostorderVisitor, ReverseFinisher, SccCollection
> ReverseSccOrder;


// this should better be implemented with iterator to walk tree
template <typename OrderType>
bool isReachable(GraphBase *graph, int src, int dest) {
    OrderType walker(graph);
    walker.gen(src);
    for(auto n : walker.get()[0]) {
        if(n == dest) {
            return true;
        }
    }
    return false;
}

typedef OrderOnCFG<
    1, PrePostorderVisitor, EmptyFinisher, NodeCollection
> PrePostOrder;

template <typename PruneType>
bool isReachable(GraphBase *graph, int src, int dest, PruneType prune) {
    PrePostOrder walker(graph);
    walker.gen(src);
    bool pruning = false;
    int pruneRoot = 0;
    for(auto n : walker.get()[0]) {
        if(pruning) {
            if(n == pruneRoot) {
                pruning = false;
            }
            continue;
        }
        if(n == dest) {
            return true;
        }
        pruning = prune(n, src, dest);
        if(pruning) {
            pruneRoot = n;
        }
    }
    return false;
}

#endif
