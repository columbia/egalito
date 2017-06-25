#ifndef EGALITO_ANALYSIS_CONTROL_FLOW_H
#define EGALITO_ANALYSIS_CONTROL_FLOW_H

#include <vector>
#include <map>
#include "util/iter.h"

class Function;
class Block;
class PLTTrampoline;

namespace ControlFlow {
    typedef int id_t;
};

class ControlFlowLink {
public:
    using id_t = ControlFlow::id_t;
private:
    id_t id;
    int offset;
    bool followJump;
public:
    ControlFlowLink(id_t id, int offset = 0, bool followJump = true)
        : id(id), offset(offset), followJump(followJump) {}

    id_t getID() const { return id; }
    int getOffset() const { return offset; }
    bool getFollowJump() const { return followJump; }
};

class ControlFlowNode {
public:
    using id_t = ControlFlow::id_t;
private:
    id_t id;
    Block *block;
private:
    typedef std::vector<ControlFlowLink> ListType;
    ListType links;
    ListType reverseLinks;
public:
    ControlFlowNode(id_t id, Block *block) : id(id), block(block) {}

    id_t getID() const { return id; }
    Block *getBlock() const { return block; }

    void addLink(const ControlFlowLink &link)
        { links.push_back(link); }
    void addReverseLink(const ControlFlowLink &rlink)
        { reverseLinks.push_back(rlink); }

    ConcreteIterable<ListType> forwardLinks()
        { return ConcreteIterable<ListType>(links); }
    ConcreteIterable<ListType> backwardLinks()
        { return ConcreteIterable<ListType>(reverseLinks); }

    ConcreteIterable<ListType> getLinks(int direction)
        { return (direction > 0) ? forwardLinks() : backwardLinks(); }

    std::string getDescription();
};

class ControlFlowGraph {
public:
    using id_t = ControlFlow::id_t;
private:
    std::vector<ControlFlowNode> graph;
    std::map<Block *, id_t> blockMapping;
public:
    ControlFlowGraph(Function *function);
    virtual ~ControlFlowGraph() {}

    ControlFlowNode *get(id_t id)
        { return &graph[id]; }
    ControlFlowNode *get(Block *block)
        { return &graph[blockMapping[block]]; }
    size_t getCount() const { return graph.size(); }

    void dump();
    void dumpDot();
private:
    void construct(Function *function);
    void construct(Block *block);
    bool doesReturn(Function *function);
    bool doesPLTReturn(PLTTrampoline *pltTrampoline);
};

#endif
