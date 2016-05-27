#ifndef EGALITO_CHUNK_H
#define EGALITO_CHUNK_H

#include <cstddef>
#include <vector>

typedef uint64_t address_t;

class Chunk {
public:
    virtual ~Chunk() {}

    virtual address_t getAddress() const = 0;
    virtual bool canMove() const { return true; }
    virtual bool moveTo(address_t newAddress) { return false; }

    virtual size_t getSize() const = 0;
    virtual void appendBytes(uint8_t *output) = 0;

    virtual std::string getName() const = 0;
};

class Function : public Chunk {
private:
    bool allReferencesKnown;
public:
    Function(bool known) : allReferencesKnown(known) {}
    
    virtual bool canMove() const { return allReferencesKnown; }
};

class Block : public Chunk {
public:
    
};

class Instruction {
public:
};

#endif
