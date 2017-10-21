#ifndef EGALITO_ANALYSIS_CONTROL_FLOW_H
#define EGALITO_ANALYSIS_CONTROL_FLOW_H

#include <vector>
#include <map>
#include "analysis/graph.h"
#include "util/iter.h"

class Function;
class Block;
class PLTTrampoline;

namespace ControlFlow {
    typedef int id_t;
};

class ControlFlowLink : public GraphLinkBase {
public:
    using id_t = ControlFlow::id_t;
private:
    id_t id;
    int offset;
    bool followJump;
public:
    ControlFlowLink(id_t id, int offset = 0, bool followJump = true)
        : id(id), offset(offset), followJump(followJump) {}

    virtual id_t getTargetID() const { return id; }
    int getOffset() const { return offset; }
    bool getFollowJump() const { return followJump; }
};

class ControlFlowNode : public GraphNodeBase {
public:
    using id_t = ControlFlow::id_t;
private:
    id_t id;
    Block *block;
private:
    using GraphNodeBase::ListType;
    ListType links;
    ListType reverseLinks;
public:
    ControlFlowNode(id_t id, Block *block) : id(id), block(block) {}
    ~ControlFlowNode() {}

    virtual id_t getID() const { return id; }
    Block *getBlock() const { return block; }

    void addLink(const ControlFlowLink &link);
    void addReverseLink(const ControlFlowLink &rlink);

    ConcreteIterable<ListType> forwardLinks()
        { return ConcreteIterable<ListType>(links); }
    ConcreteIterable<ListType> backwardLinks()
        { return ConcreteIterable<ListType>(reverseLinks); }

    virtual ConcreteIterable<ListType> getLinks(int direction)
        { return (direction > 0) ? forwardLinks() : backwardLinks(); }

    std::string getDescription();
};

class ControlFlowGraph : public GraphBase {
public:
    using id_t = ControlFlow::id_t;
private:
    std::vector<ControlFlowNode> graph;
    std::map<Block *, id_t> blockMapping;
public:
    ControlFlowGraph(Function *function);
    virtual ~ControlFlowGraph();

    virtual ControlFlowNode *get(id_t id)
        { return &graph[id]; }
    virtual size_t getCount() const { return graph.size(); }

    id_t getIDFor(Block *block) { return blockMapping[block]; }

    void dump();
    void dumpDot();
private:
    void construct(Function *function);
    void construct(Block *block);
    bool doesReturn(Function *function);
    bool doesPLTReturn(PLTTrampoline *pltTrampoline);
};

#endif
