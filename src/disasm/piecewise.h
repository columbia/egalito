#ifndef EGALITO_DISASM_PIECEWISE_H
#define EGALITO_DISASM_PIECEWISE_H

#include <vector>
#include "chunk/chunk.h"

class SymbolList;
class BlockSoup;

class UnionFind {
private:
    std::vector<size_t> parent;
public:
    UnionFind(size_t count);

    void join(size_t one, size_t two);
    size_t get(size_t where);

    size_t getCount() const { return parent.size(); }
};

class PiecewiseDisassemble {
private:
    BlockSoup *soup;
public:
    void linearPass(address_t readAddress, size_t codeLength,
        address_t trueAddress);
};

#endif
