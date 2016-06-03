#ifndef EGALITO_CHUNK_H
#define EGALITO_CHUNK_H

#include <cstdint>
#include <vector>
#include <memory>  // for std::shared_ptr
#include <capstone/capstone.h>  // for cs_insn
#include "elf/symbol.h"
#include "position.h"
#include "types.h"

class Sandbox;

class Chunk {
public:
    virtual ~Chunk() {}

    /** Returns the enclosing Chunk, if any. */
    virtual Chunk *getParent() = 0;

    virtual address_t getAddress() const = 0;
    virtual void setAddress(address_t address) = 0;
    virtual size_t getSize() const = 0;
    virtual void setSize(size_t size) = 0;
    virtual void invalidateSize() = 0;

    virtual bool contains(address_t address) = 0;
    virtual bool contains(address_t address, size_t size) = 0;

    /** Returns an identifier for this Chunk. This is only guaranteed to be
        unique amongst its siblings in any enclosing Chunk.
    */
    virtual std::string getName() const = 0;
    virtual int getVersion() const = 0;
    virtual void setVersion(int version) = 0;

    /** Generates a copy of this Chunk in the output Sandbox. The sandbox
        address is assumed to have been passed to setAddress() earlier.
    */
    virtual void writeTo(Sandbox *sandbox) = 0;
};

template <typename PositionType>
class ChunkImpl : public Chunk {
private:
    PositionType position;
public:
    ChunkImpl(address_t address, size_t size);
    virtual Chunk *getParent() { return nullptr; }

    virtual address_t getAddress() const;
    virtual void setAddress(address_t address);

    virtual bool contains(address_t address);
    virtual bool contains(address_t address, size_t size);

    virtual int getVersion() const { return 0; }
    virtual void setVersion(int version);
protected:
    const PositionType &getPosition() const { return position; }
    PositionType &getPosition() { return position; }
    void setPosition(const PositionType &p) { position = p; }
};

template <typename ParentType>
class ChildImpl {
private:
    ParentType *parent;
public:
    ChildImpl(ParentType *parent = nullptr) : parent(parent) {}

    virtual ParentType *getParent() { return parent; }
    void setParent(ParentType *parent) { this->parent = parent; }

    virtual void invalidateSize();
};

template <typename ChildType>
class CompositeImpl {
protected:
    typedef std::vector<ChildType *> ChildListType;
private:
    ChildListType childList;
    mutable CalculatedSize size;
public:
    CompositeImpl() : size(0, false) {}

    virtual size_t getSize() const;
    virtual void setSize(size_t size);
    virtual void invalidateSize() { size.invalidate(); }

    typename ChildListType::iterator begin() { return childList.begin(); }
    typename ChildListType::iterator end() { return childList.end(); }
protected:
    ChildListType &children() { return childList; }
    const ChildListType &children() const { return childList; }

    const CalculatedSize &getCalculatedSize() const { return size; }
    CalculatedSize &getCalculatedSize() { return size; }
};

class Block;

class Function : public ChunkImpl<NormalPosition>,
    public CompositeImpl<Block> {
private:
    Symbol *symbol;
public:
    Function(Symbol *symbol) : ChunkImpl(symbol->getAddress(), 0),
        symbol(symbol) {}
    void append(Block *block);

    using CompositeImpl<Block>::getSize;
    using CompositeImpl<Block>::invalidateSize;

    virtual std::string getName() const { return symbol->getName(); }

    virtual void writeTo(Sandbox *sandbox);
};

class Instruction;

class Block : public ChunkImpl<RelativePosition>,
    public ChildImpl<Function>, public CompositeImpl<Instruction> {
private:
    std::string name;
public:
    Block(std::string name, address_t address)
        : ChunkImpl<RelativePosition>(address, 0), name(name) {}
    Instruction *append(Instruction instr);

    using ChildImpl<Function>::getParent;
    using CompositeImpl<Instruction>::getSize;

    virtual void invalidateSize();

    size_t getOffset() const { return getPosition().getOffset(); }
    void setOffset(size_t offset) { getPosition().setOffset(offset); }

    virtual std::string getName() const { return name; }
    void setName(const std::string &name) { this->name = name; }

    virtual void writeTo(Sandbox *sandbox);
};


class NativeInstruction {
private:
    bool cached;
    cs_insn insn;
    Instruction *instr;
public:
    NativeInstruction(Instruction *instr) : cached(false), instr(instr) {}
    NativeInstruction(Instruction *instr, const cs_insn &insn)
        : cached(true), insn(insn), instr(instr) {}

    void invalidate() { cached = false; }
    void regenerate();
    cs_insn &raw();
};

class Instruction : public ChunkImpl<RelativePosition>,
    public ChildImpl<Block> {
private:
    std::string data;
    KnownSourceLink<RelativePosition> *link;
    NativeInstruction native;
    OriginalPosition originalAddress;
public:
    Instruction(std::string data, address_t originalAddress);
    Instruction(cs_insn insn);

    using ChildImpl<Block>::getParent;
    virtual void setParent(Block *parent);
    virtual size_t getSize() const { return data.size(); }
    virtual void setSize(size_t size);
    virtual void invalidateSize();

    size_t getOffset() const { return getPosition().getOffset(); }
    void setOffset(size_t offset) { getPosition().setOffset(offset); }

    void makeLink(address_t source, address_t target);
    bool hasLink() const { return link != nullptr; }
    KnownSourceLink<RelativePosition> *getLink() { return link; }

    virtual std::string getName() const { return getRawData(); }

    virtual void writeTo(Sandbox *sandbox);

    std::string getRawData() const { return data; }
    cs_insn &getNative() { return native.raw(); }
    void dump();
};

#endif
