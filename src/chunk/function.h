#ifndef EGALITO_CHUNK_FUNCTION_H
#define EGALITO_CHUNK_FUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "block.h"
#include "archive/archive.h"

class Symbol;
class Function : public ChunkSerializerImpl<CompositeChunkImpl<Block>,
    EgalitoArchive::TYPE_Function> {
public:
    virtual Symbol *getSymbol() const = 0;
    virtual std::string getName() const = 0;
    virtual bool hasName(std::string name) const = 0;

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

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
    FuzzyFunction() {}
    FuzzyFunction(address_t originalAddress);

    virtual Symbol *getSymbol() const { return nullptr; }
    virtual std::string getName() const { return name; }
    virtual bool hasName(std::string name) const
        { return name == this->name; }

    void setName(std::string name) { this->name = name; }
};

class FunctionList : public ChunkSerializerImpl<CompositeChunkImpl<Function>,
    EgalitoArchive::TYPE_FunctionList> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);
};

#endif
