#ifndef EGALITO_CHUNK_H
#define EGALITO_CHUNK_H

#include <cstdint>
#include <vector>
#include <memory>  // for std::shared_ptr
#include <capstone/capstone.h>  // for cs_insn
#include "elf/symbol.h"
#include "types.h"

class Slot;
class Sandbox;

class Chunk {
public:
    virtual ~Chunk() {}

    virtual address_t getAddress() const = 0;
    virtual size_t getSize() const = 0;

    virtual std::string getName() const = 0;
    virtual int getVersion() const { return 0; }

    virtual void sizeChanged(ssize_t bytesAdded) = 0;
    virtual void writeTo(Slot *slot) = 0;
};

class Block;

class Function : public Chunk {
private:
    Symbol *symbol;
    address_t address;
    size_t size;
    typedef std::vector<Block *> BlockListType;
    BlockListType blockList;
public:
    Function(Symbol *symbol) : symbol(symbol),
        address(symbol->getAddress()), size(0) {}
    void append(Block *block);

    virtual address_t getAddress() const { return address; }
    virtual size_t getSize() const { return size; }

    virtual std::string getName() const { return symbol->getName(); }

    BlockListType::iterator begin() { return blockList.begin(); }
    BlockListType::iterator end() { return blockList.end(); }

    virtual void sizeChanged(ssize_t bytesAdded);
    virtual void writeTo(Slot *slot);
};

class Instruction;

class Block : public Chunk {
private:
    std::string name;
    size_t offset;
    size_t size;
    typedef std::vector<Instruction> InstrListType;
    InstrListType instrList;
    Function *outer;
public:
    Block() : offset(0), size(0), outer(nullptr) {}
    void append(Instruction instr);

    virtual address_t getAddress() const;
    virtual size_t getSize() const { return size; }
    size_t getOffset() const { return offset; }
    Function *getOuter() const { return outer; }

    virtual std::string getName() const { return name; }

    void setOuter(Function *outer) { this->outer = outer; }
    void setName(const std::string &name) { this->name = name; }
    void setOffset(size_t offset) { this->offset = offset; }

    InstrListType::iterator begin() { return instrList.begin(); }
    InstrListType::iterator end() { return instrList.end(); }

    virtual void sizeChanged(ssize_t bytesAdded);
    virtual void writeTo(Slot *slot);
};

class Instruction {
private:
    enum detail_t {
        DETAIL_NONE,
        DETAIL_CAPSTONE
    } detail;

    std::string data;
    cs_insn insn;
    size_t offset;
    Block *outer;
public:
    Instruction(std::string data) : detail(DETAIL_NONE), data(data),
        offset(0), outer(nullptr) {}
    Instruction(cs_insn insn) : detail(DETAIL_CAPSTONE), insn(insn),
        offset(0), outer(nullptr) {}

    cs_insn &raw() { return insn; }
    virtual address_t getAddress() const;
    size_t getSize() const;

    void setOuter(Block *outer) { this->outer = outer; }
    void setOffset(size_t offset) { this->offset = offset; }

    void writeTo(Slot *slot);
    void dump();
};

#endif
