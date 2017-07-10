#ifndef EGALITO_ANALYSIS_WALKER_H
#define EGALITO_ANALYSIS_WALKER_H

#include <vector>
#include <algorithm>
#include "controlflow.h"
#include "util/iter.h"

template <typename DerivedType>
class DFSWalkerBase {
private:
    ControlFlowGraph *cfg;
    std::vector<bool> visited;

protected:
    DFSWalkerBase(ControlFlowGraph *cfg) : cfg(cfg) {}
    void walk(int id, int dir) {
        visited.assign(cfg->getCount(), false);
        reset();
        walkHelper(id, dir);
        finish();
    }

    void walkAll(int id, int dir) {
        visited.assign(cfg->getCount(), false);
        reset();
        walkHelper(id, dir);
        for(size_t i = 1; i < cfg->getCount(); i++) {
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
        preVisit(cfg->get(id));
        for(auto &link : cfg->get(id)->getLinks(dir)) {
            auto n = link.getID();
            if(!visited[n]) {
                walkHelper(link.getID(), dir);
            }
            else {
                lateVisit(cfg->get(id), &link);
            }
        }
        postVisit(cfg->get(id));
    };

    DerivedType &derived() {
        return *static_cast<DerivedType *>(this);
    }

    void reset() { derived().reset(); }
    void tick() { derived().tick(); }
    void finish() { derived().finish(); }
    void preVisit(ControlFlowNode *node) { derived().preVisit(node); }
    void postVisit(ControlFlowNode *node) { derived().postVisit(node); }
    void lateVisit(ControlFlowNode *from, ControlFlowLink *link)
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
    NodeCollection(ControlFlowGraph *cfg)
        : order(cfg->getCount()), lap(0) {}

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
    void preVisit(ControlFlowNode *node) {
        VisitType().preVisit(&order[lap], node->getID());
    }
    void postVisit(ControlFlowNode *node) {
        VisitType().postVisit(&order[lap], node->getID());
    }
    void lateVisit(ControlFlowNode *from, ControlFlowLink *link) { }
    void finish() {
        for(auto& o : order) {
            FinishType().finish(&o);
        }
    }
};

template <int Direction, typename VisitType, typename FinishType>
class SccCollection {
private:
    ControlFlowGraph *cfg;
    int scc;
    int disc;
    std::vector<int> discovery;
    std::vector<int> lowLink;
    std::vector<bool> onStack;
    std::vector<int> stack;
    std::vector<int> poStack;
    std::vector<std::vector<int>> sccOrder;

public:
    SccCollection(ControlFlowGraph *cfg)
        : cfg(cfg), scc(0), disc(0),
          discovery(cfg->getCount()), lowLink(cfg->getCount()),
          onStack(cfg->getCount()) {}

    const std::vector<std::vector<int>>& get() const { return sccOrder; }

    void reset() {
        scc = 0;
        disc = 0;
        sccOrder.clear();
        sccOrder.push_back(std::vector<int>());
    }
    void tick() {}
    void preVisit(ControlFlowNode *node) {
        discovery[node->getID()] = disc;
        lowLink[node->getID()] = disc;
        stack.push_back(node->getID());
        onStack[node->getID()] = true;
        ++disc;
    }
    void postVisit(ControlFlowNode *node) {
        for(const auto& link : node->getLinks(Direction)) {
            if(discovery[node->getID()] < discovery[link.getID()]) {
                lowLink[node->getID()] = std::min(lowLink[node->getID()],
                                                  lowLink[link.getID()]);
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
    void lateVisit(ControlFlowNode *from, ControlFlowLink *link) {
        if(onStack[link->getID()]) {
            lowLink[from->getID()] = std::min(lowLink[from->getID()],
                                              discovery[link->getID()]);
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
    template <int, typename, typename> typename CollectType
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
    OrderOnCFG(ControlFlowGraph *cfg)
        : BaseType(cfg), collector(cfg) {}

    void gen(int id) { BaseType::walk(id, Direction); }
    void genFull(int id) { BaseType::walkAll(id, Direction); }

    const std::vector<std::vector<int>>& get() const
        { return collector.get(); }

private:
    void reset() { collector.reset(); }
    void tick() { collector.tick(); }
    void preVisit(ControlFlowNode *node) { collector.preVisit(node); }
    void postVisit(ControlFlowNode *node) { collector.postVisit(node); }
    void lateVisit(ControlFlowNode *from, ControlFlowLink *link)
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
bool isReachable(ControlFlowGraph *cfg, int src, int dest) {
    OrderType walker(cfg);
    walker.gen(src);
    for(auto n : walker.get()[0]) {
        if(n == dest) {
            return true;
        }
    }
    return false;
}

#endif
