#ifndef EGALITO_ANALYSIS_CALL_H
#define EGALITO_ANALYSIS_CALL_H

#include <vector>
#include <set>
#include <map>
#include <bitset>
#include "analysis/graph.h"
#include "util/iter.h"

class Module;
class Program;
class Function;

class CallGraphLink : public GraphLinkBase {
private:
    int targetId;
public:
    CallGraphLink(int targetId) : targetId(targetId) {}
    virtual int getTargetID() const { return targetId; }
};

class CallGraphNode : public GraphNodeBase {
private:
    int id;
    Function *function;
    using GraphNodeBase::ListType;
    ListType upLinks;
    ListType downLinks;

public:
    CallGraphNode(int id, Function *function) : id(id), function(function) {}
    ~CallGraphNode() {}
    Function *getFunction() const { return function; }
    virtual int getID() const { return id; }

    void addDownLink(int targetId);
    void addUpLink(int targetId);
    bool root() const { return upLinks.empty(); }
    bool leaf() const { return downLinks.empty(); }

    ConcreteIterable<ListType> downwardLinks()
        { return ConcreteIterable<ListType>(downLinks); }
    ConcreteIterable<ListType> upwardLinks()
        { return ConcreteIterable<ListType>(upLinks); }

    virtual ConcreteIterable<ListType> getLinks(int direction)
        { return (direction > 0) ? downwardLinks() : upwardLinks(); }
};

class CallGraph : public GraphBase {
private:
    std::vector<CallGraphNode> nodeList;
    std::map<Function *, int> mapping;
public:
    CallGraph(Program *program);
    virtual ~CallGraph();
    CallGraphNode *getNode(Function *function)
        { return &nodeList[mapping[function]]; }
    Function *getFunction(int id) { return nodeList[id].getFunction(); }
    int getIDFor(Function *function) { return mapping[function]; }
    virtual CallGraphNode *get(int id) { return &nodeList[id]; }
    virtual size_t getCount() const { return nodeList.size(); }
private:
    void makeDirectEdges(Function *function);
    void makeLinks(Function *caller, Function *callee);
};

class IndirectCalleeList {
private:
    std::set<Function *> indirectCalleeList;
public:
    IndirectCalleeList(Program *program);
    IndirectCalleeList(Module *module);
    bool contains(Function *function);
    const std::set<Function *>& getList() const { return indirectCalleeList; }
private:
    void makeList(Module *module);
};

#endif
