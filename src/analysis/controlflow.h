#ifndef EGALITO_ANALYSIS_CONTROL_FLOW_H
#define EGALITO_ANALYSIS_CONTROL_FLOW_H

#include <vector>
#include <map>
#include <utility>
#include "util/iter.h"

class Function;
class Block;

class ControlFlowNode {
public:
    typedef int id_t;
private:
    id_t id;
    Block *block;
private:
    typedef std::vector<std::pair<id_t, int>> ListType;
    ListType links;
    ListType reverseLinks;
public:
    ControlFlowNode(id_t id, Block *block) : id(id), block(block) {}

    id_t getID() const { return id; }
    Block *getBlock() const { return block; }

    void addLink(id_t other, int offset = 0)
        { links.push_back(std::make_pair(other, offset)); }
    void addReverseLink(id_t other, int offset = 0)
        { reverseLinks.push_back(std::make_pair(other, offset)); }

    ConcreteIterable<ListType> forwardLinks()
        { return ConcreteIterable<ListType>(links); }
    ConcreteIterable<ListType> backwardLinks()
        { return ConcreteIterable<ListType>(reverseLinks); }

    std::string getDescription();
};

class ControlFlowGraph {
private:
    std::vector<ControlFlowNode> graph;
    std::map<Block *, ControlFlowNode::id_t> blockMapping;
public:
    ControlFlowGraph(Function *function);

    ControlFlowNode *get(ControlFlowNode::id_t id)
        { return &graph[id]; }
    ControlFlowNode *get(Block *block)
        { return &graph[blockMapping[block]]; }
    size_t getCount() const { return graph.size(); }

    void dump();
private:
    void construct(Function *function);
    void construct(Block *block);
};

#endif
