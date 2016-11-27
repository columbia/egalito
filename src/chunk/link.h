#ifndef EGALITO_CHUNK_LINK_H
#define EGALITO_CHUNK_LINK_H

#include "chunkref.h"

class Link {
private:
    ChunkRef target;
public:
    LinkAttribute(ChunkRef target) : target(target) {}
    ChunkRef getTarget() const { return target; }
};

class XRef {
private:
    ChunkRef source;
    Link *link;
public:
    XRef(ChunkRef source, Link *link) : source(source), link(link) {}

    ChunkRef getSource() const { return source; }
    ChunkRef getTarget() const { return link->getTarget(); }
};

class XRefDatabase {
private:
    typedef std::vector<XRef> DatabaseType;
    DatabaseType database;
public:
    void add(XRef xref) { database.push_back(xref); }

    IterableImpl<DatabaseType> iterable()
        { return IterableImpl<DatabaseType>(database); }
};

#endif
