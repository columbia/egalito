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

    //virtual void sizeChanged(ssize_t bytesAdded) = 0;
    virtual void writeTo(Slot *slot) = 0;
};

class Block;

class Function : public Chunk {
private:
    Slot *slot;
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

    void setAddress(address_t newAddress);
    void updateAddress();

    BlockListType::iterator begin() { return blockList.begin(); }
    BlockListType::iterator end() { return blockList.end(); }

    virtual void sizeChanged(ssize_t bytesAdded, Block *which);
    void prepareWrite(Slot *slot);
    virtual void writeTo(Slot *_unused);
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
    Instruction *append(Instruction instr);

    virtual address_t getAddress() const;
    virtual size_t getSize() const { return size; }
    size_t getOffset() const { return offset; }
    Function *getOuter() const { return outer; }

    virtual std::string getName() const { return name; }

    void setOuter(Function *outer) { this->outer = outer; }
    void setName(const std::string &name) { this->name = name; }
    void setOffset(size_t offset);

    InstrListType::iterator begin() { return instrList.begin(); }
    InstrListType::iterator end() { return instrList.end(); }

    virtual void sizeChanged(ssize_t bytesAdded);
    virtual void writeTo(Slot *slot);
};

class CodeReference;

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
    bool fixup;
    CodeReference *target;
    address_t originalAddress;
    address_t originalTarget;
private:
    void regenerate();
public:
    Instruction(std::string data) : detail(DETAIL_NONE), data(data),
        offset(0), outer(nullptr), fixup(false) {}
    Instruction(cs_insn insn) : detail(DETAIL_CAPSTONE), insn(insn),
        offset(0), outer(nullptr), fixup(false) {}

    cs_insn &raw() { return insn; }
    virtual address_t getAddress() const;
    size_t getSize() const;

    void setOuter(Block *outer) { this->outer = outer; }
    void setOffset(size_t offset);
    void setFixup(bool on) { fixup = on; }
    void setOriginalAddress(address_t a) { originalAddress = a; }
    void setOriginalTarget(address_t a) { originalTarget = a; }
    void setCodeReference(CodeReference *c) { target = c; }

    bool hasFixup() const { return fixup; }
    CodeReference *getCodeReference() const { return target; }

    void writeTo(Slot *slot);
    void dump();
};

class CodeReference {
private:
    address_t source;
    enum { FIXED, CHUNK } type;
    address_t fixedAddress;
    Chunk *chunk;
    size_t offset;
public:
    CodeReference(address_t source, address_t fixedAddress)
        : source(source), type(FIXED), fixedAddress(fixedAddress) {}
    CodeReference(address_t source, Chunk *chunk, size_t offset = 0)
        : source(source), type(CHUNK), chunk(chunk), offset(offset) {}

    bool hasChunkTarget() const { return type == CHUNK; }
    address_t getSource() const { return source; }
    address_t getTarget();
};

#if 0
class CodeReference {
private:
    Instruction *instr;
    size_t sourceOffset;
    Chunk *target;
    size_t destOffset;
public:
    Fixup(Instruction *instr, size_t offset)
        : instr(instr), offset(offset) {}
};
#endif

#endif
