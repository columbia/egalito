#ifndef EGALITO_CHUNK_H
#define EGALITO_CHUNK_H

#include <cstdint>
#include <vector>
#include <memory>  // for std::shared_ptr
#include "types.h"

class Slot;
class Sandbox;
class Symbol;

class Chunk {
public:
    virtual ~Chunk() {}

    virtual address_t getAddress() const = 0;
    virtual bool canMove() const { return true; }
    virtual bool moveTo(address_t newAddress) { return false; }

    virtual size_t getSize() const = 0;
    virtual void writeTo(Slot *slot) = 0;

    virtual std::string getName() const = 0;
};

class Block;

class Function : public Chunk {
private:
    Symbol *symbol;
    bool allReferencesKnown;
    std::vector<std::shared_ptr<Block>> blockList;
public:
    Function(Symbol *symbol, bool known)
        : symbol(symbol), allReferencesKnown(known) {}
    
    virtual bool canMove() const { return allReferencesKnown; }
    virtual void writeTo(Slot *slot);

    std::vector<std::shared_ptr<Block>>::iterator begin()
        { return blockList.begin(); }
    std::vector<std::shared_ptr<Block>>::iterator end()
        { return blockList.end(); }
};

class Block : public Chunk {
public:
    virtual void writeTo(Slot *slot);
};

class Instruction {
public:
};

#endif
