#ifndef EGALITO_CHUNK_FUNCTION_H
#define EGALITO_CHUNK_FUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "block.h"
#include "archive/chunktypes.h"

class Symbol;
class Function;
class ChunkCache;

class Function : public ChunkSerializerImpl<TYPE_Function,
    AssignableCompositeChunkImpl<Block>> {
private:
    Symbol *symbol;
    Symbol *dynamicSymbol;  // !!! not serialized
    std::string name;
    bool nonreturn;
    bool ifunc;
    ChunkCache *cache;
public:
    Function() : symbol(nullptr), dynamicSymbol(nullptr), nonreturn(false),
        ifunc(false), cache(nullptr) {}

    /** Create a fuzzy function named according to the original address. */
    Function(address_t originalAddress);

    /** Create an authoritative function from symbol information. */
    Function(Symbol *symbol);

    Symbol *getSymbol() const { return symbol; }
    Symbol *getDynamicSymbol() const { return dynamicSymbol; }
    virtual void setDynamicSymbol(Symbol *ds) { dynamicSymbol = ds; }
    virtual std::string getName() const { return name; }
    virtual void setName(const std::string &name) { this->name = name; }

    /** Check if the given name is a valid alias for this function. */
    virtual bool hasName(std::string name) const;

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);

    bool returns() const { return !nonreturn; }
    void setNonreturn() { nonreturn = true; }
    bool isIFunc() const { return ifunc; }
    void setIsIFunc(bool yes) { ifunc = yes; }

    void makeCache();
    ChunkCache *getCache() const { return cache; }
};

class FunctionList : public ChunkSerializerImpl<TYPE_FunctionList,
    CollectionChunkImpl<Function>> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);
    virtual std::string getName() const { return "functionlist"; }

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);
};

#endif
