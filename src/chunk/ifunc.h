#ifndef EGALITO_CHUNK_IFUNC_H
#define EGALITO_CHUNK_IFUNC_H

#include <vector>
#include <map>
#include "chunk/chunk.h"
#include "chunk/chunklist.h"

class IFunc : public AddressableChunkImpl {
private:
    Chunk *target;
public:
    IFunc(Chunk *target) : target(target) {}
    address_t getAddress() const { return target->getAddress(); }
    virtual void accept(ChunkVisitor *visitor) {}
};

class IFuncList : public CollectionChunkImpl<IFunc> {
public:
    using IFuncType = void *(*)();
private:
    std::map<address_t, IFunc *> map;
public:
    void add(address_t address, Chunk *target);
    void *getFor(address_t address) const;
    virtual void accept(ChunkVisitor *visitor) {}
};

#endif
