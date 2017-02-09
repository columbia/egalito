#ifndef EGALITO_DISASM_PIECEWISE_H
#define EGALITO_DISASM_PIECEWISE_H

#include <vector>
#include "chunk/chunk.h"

class SymbolList;
class Block;

class PiecewiseDisassemble {
private:
    std::vector<Block *> blockList;
public:
    void linearPass(address_t readAddress, size_t codeLength,
        address_t trueAddress);
};

#endif
