#ifndef EGALITO_ELF_UNIONFIND_H
#define EGALITO_ELF_UNIONFIND_H

#include <vector>
#include <cstddef>

class UnionFind {
protected:
    std::vector<size_t> parent;

public:
    UnionFind(size_t count);
    virtual ~UnionFind() {}

    void join(size_t x1, size_t x2);
    size_t find(size_t x);

private:
    virtual void setEdge(size_t x1, size_t x2);
};

#endif
