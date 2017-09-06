#ifndef EGALITO_CHUNK_FUNCTION_H
#define EGALITO_CHUNK_FUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "block.h"

class Symbol;
class Function : public CompositeChunkImpl<Block> {
public:
    virtual Symbol *getSymbol() const = 0;
    virtual std::string getName() const = 0;
    virtual bool hasName(std::string name) const = 0;

    virtual void accept(ChunkVisitor *visitor);
};

class FunctionFromSymbol : public Function {
private:
    Symbol *symbol;
public:
    FunctionFromSymbol(Symbol *symbol) : symbol(symbol) {}

    virtual Symbol *getSymbol() const { return symbol; }
    virtual std::string getName() const;
    virtual bool hasName(std::string name) const;
};

class FuzzyFunction : public Function {
private:
    std::string name;
public:
    FuzzyFunction(address_t originalAddress);

    virtual Symbol *getSymbol() const { return nullptr; }
    virtual std::string getName() const { return name; }
    virtual bool hasName(std::string name) const
        { return name == this->name; }
};

class FunctionList : public CompositeChunkImpl<Function> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);
};

#endif
