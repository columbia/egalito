#ifndef EGALITO_CHUNK_FUNCTION_H
#define EGALITO_CHUNK_FUNCTION_H

#include "chunk.h"
#include "chunklist.h"
#include "block.h"
#include "archive/chunktypes.h"

class Symbol;
class Function : public ChunkSerializerImpl<TYPE_Function,
    CompositeChunkImpl<Block>> {
private:
    Symbol *symbol;
    std::string name;
public:
    Function() : symbol(nullptr) {}

    /** Create a fuzzy function named according to the original address. */
    Function(address_t originalAddress);

    /** Create an authoritative function from symbol information. */
    Function(Symbol *symbol);

    virtual Symbol *getSymbol() const { return symbol; }
    virtual std::string getName() const { return name; }
    virtual void setName(const std::string &name) { this->name = name; }

    /** Check if the given name is a valid alias for this function. */
    virtual bool hasName(std::string name) const;

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class FunctionList : public ChunkSerializerImpl<TYPE_FunctionList,
    CompositeChunkImpl<Function>> {
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
