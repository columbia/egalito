#ifndef EGALITO_CHUNK_H
#define EGALITO_CHUNK_H

#include <cstdint>
#include <vector>
#include <memory>  // for std::shared_ptr
#include <capstone/capstone.h>  // for cs_insn
#include "elf/symbol.h"
#include "observer.h"  // for EventObserverRegistry
#include "position.h"  // for Position
#include "link.h"  // for Link, XRefDatabase
#include "types.h"

class Sandbox;

template <typename ChildType> class ChunkList;

class ChunkVisitor;

/** Chunks represent pieces of code arranged in a hierarchical structure.
*/
class Chunk {
public:
    virtual ~Chunk() {}

    virtual EventObserverRegistry *getRegistry() = 0;

    virtual Chunk *getParent() const = 0;
    virtual void setParent(Chunk *newParent) = 0;
    virtual ChunkList<Chunk *> *getChildren() const = 0;
    virtual Position *getPosition() const = 0;
    virtual void setPosition(Position *newPosition) = 0;
    virtual size_t getSize() const = 0;
    virtual void setSize(size_t newSize) = 0;
    virtual XRefDatabase *getDatabase() const = 0;

    virtual address_t getAddress() const = 0;

    virtual void accept(ChunkVisitor *visitor) = 0;
};

class ChunkImpl : public Chunk {
private:
    EventObserverRegistry registry;
    Chunk *parent;
    Position *position;
public:
    ChunkImpl(Chunk *parent = nullptr, Position *position = nullptr)
        : parent(parent), position(position) {}
    virtual EventObserverRegistry *getRegistry() { return &registry; }

    virtual Chunk *getParent() const { return parent; }
    virtual void setParent(Chunk *newParent) { parent = newParent; }
    virtual ChunkList<Chunk *> *getChildren() const { return nullptr; }
    virtual Position *getPosition() const { return position; }
    virtual void setPosition(Position *newPosition) { position = newPosition; }
    virtual size_t getSize() const { return 0; }
    virtual XRefDatabase *getDatabase() const { return nullptr; }

    virtual address_t getAddress() const { return getPosition()->get(); }
};

template <typename ChunkType, typename ChildType>
class ChildListDecorator : public ChunkType {
private:
    ChunkList<ChildType> childList;
public:
    virtual ChunkList<ChildType *> *getChildren() const { return &childList; }
};

template <typename ChildType>
class CompositeChunkImpl : public ChildListDecorator<ChunkImpl, ChildType> {
};

template <typename ChunkType>
class XRefDecorator : public ChunkType {
private:
    XRefDatabase database;
public:
    virtual XRefDatabase *getDatabase() const { return &database; }

    virtual void handle(AddLinkEvent e)
        { database.add(XRef(e.getOrigin(), e.getLink())); ChunkType::handle(e); }
};

// --- concrete Chunk implementations follow ---

class Program;
class CodePage;
class Function;
class Block;
class Instruction;

class ChunkVisitor {
public:
    virtual ~ChunkVisitor() {}
    virtual void visit(Program *program) = 0;
    virtual void visit(CodePage *codePage) = 0;
    virtual void visit(Function *function) = 0;
    virtual void visit(Block *block) = 0;
    virtual void visit(Instruction *instruction) = 0;
};
class ChunkListener {
public:
    virtual void visit(Program *program) {}
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Function *function) {}
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
};

class Program : public ChunkImpl {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class CodePage : public XRefDecorator<CompositeChunkImpl<Block>> {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class Function : public CompositeChunkImpl<Block> {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class Block : public CompositeChunkImpl<Instruction> {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
};
class InstructionSemantic;
class Instruction : public ChunkImpl {
private:
    InstructionSemantic *semantic;
public:
    Instruction(InstructionSemantic *semantic)
        : semantic(semantic), delegatedSize(semantic) {}

    InstructionSemantic *getSemantic() const { return semantic; }
    void setSemantic(InstructionSemantic *semantic);

    virtual size_t getSize() const { return semantic->getSize(); }
    virtual void setSize(size_t value) { semantic->setSize(value); }

    virtual void accept(ChunkVisitor *visitor) { visitor->visit(this); }
    void accept(SemanticVisitor *visitor) { semantic->accept(visitor); }
};

#if 0
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
    ChunkImpl(PositionType position) : position(position) {}
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
    Function(Symbol *symbol) : ChunkImpl(symbol->getAddress()),
        symbol(symbol) {}
    void append(Block *block);

    virtual size_t getSize() const
        { return CompositeImpl<Block>::getSize(); }
    virtual void setSize(size_t size)
        { CompositeImpl<Block>::setSize(size); }
    virtual void invalidateSize()
        { CompositeImpl<Block>::invalidateSize(); }

    virtual std::string getName() const { return symbol->getName(); }

    virtual void writeTo(Sandbox *sandbox);
};

class Instruction;

class Block : public ChunkImpl<RelativePosition>,
    public ChildImpl<Function>, public CompositeImpl<Instruction> {
private:
    std::string name;
public:
    Block() : ChunkImpl(RelativePosition(nullptr, 0)) {}
    Instruction *append(Instruction *instr);
    void setRelativeTo(Chunk *outside)
        { getPosition().setRelativeTo(outside); }

    virtual Function *getParent()
        { return ChildImpl<Function>::getParent(); }
    virtual void setParent(Function *parent);
    virtual size_t getSize() const
        { return CompositeImpl<Instruction>::getSize(); }
    virtual void setSize(size_t size)
        { CompositeImpl<Instruction>::setSize(size); }

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

    virtual Block *getParent()
        { return ChildImpl<Block>::getParent(); }
    virtual void setParent(Block *parent);
    virtual size_t getSize() const { return data.size(); }
    virtual void setSize(size_t size);
    virtual void invalidateSize();

    size_t getOffset() const { return getPosition().getOffset(); }
    void setOffset(size_t offset) { getPosition().setOffset(offset); }
    void setRelativeTo(Chunk *outside)
        { getPosition().setRelativeTo(outside); }
    bool hasRelativeTo() const { return getPosition().hasRelativeTo(); }

    void makeLink(address_t sourceOffset, Position *target);
    bool hasLink() const { return link != nullptr; }
    KnownSourceLink<RelativePosition> *getLink() { return link; }

    virtual std::string getName() const { return getRawData(); }

    virtual void writeTo(Sandbox *sandbox);

    std::string getRawData() const { return data; }
    cs_insn &getNative() { return native.raw(); }
    void dump();
};
#endif

#endif
