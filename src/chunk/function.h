#ifndef EGALITO_CHUNK_FUNCTION_H
#define EGALITO_CHUNK_FUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "block.h"

class Symbol;
class Function : public CompositeChunkImpl<Block> {
private:
    Symbol *symbol;
public:
    Function(Symbol *symbol) : symbol(symbol) {}

    Symbol *getSymbol() const { return symbol; }
    std::string getName() const;

    virtual void accept(ChunkVisitor *visitor);
};

class FunctionList : public CompositeChunkImpl<Function> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);
};

#endif
