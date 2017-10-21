#ifndef EGALITO_ANALYSIS_GRAPH_H
#define EGALITO_ANALYSIS_GRAPH_H

#include <vector>
#include <cstddef>
#include "util/iter.h"

class GraphLinkBase {
public:
    virtual ~GraphLinkBase() {}
    virtual int getTargetID() const = 0;
};

class GraphLinkRef {
private:
    GraphLinkBase *link;
public:
    GraphLinkRef(GraphLinkBase *link) : link(link) {}
    GraphLinkBase &operator * () const { return *link; }
    GraphLinkBase *operator -> () const { return link; }
};

class GraphNodeBase {
public:
    typedef std::vector<GraphLinkRef> ListType;
    virtual int getID() const = 0;
    virtual ConcreteIterable<ListType> getLinks(int direction) = 0;
};

class GraphBase {
public:
    virtual GraphNodeBase *get(int id) = 0;
    virtual size_t getCount() const = 0;
};


#endif
