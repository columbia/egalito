#include "unionfind.h"

UnionFind::UnionFind(size_t count) {
    for(size_t i = 0; i < count; i++) {
        parent.push_back(i);
    }
}

void UnionFind::join(size_t x1, size_t x2) {
    auto p1 = find(x1);
    auto p2 = find(x2);
    setEdge(p1, p2);
}

size_t UnionFind::find(size_t x) {
    while(parent[x] != x) { x = parent[x]; }
    return x;
}

void UnionFind::setEdge(size_t x1, size_t x2) {
    if(x1 < x2) parent[x2] = x1;
    if(x1 > x2) parent[x1] = x2;
}

