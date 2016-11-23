#include <string>
#include "types.h"

class Chunk;
class ChunkReference;

template <typename ValueType>
class Iterator {
public:
    ValueType next();
    bool hasNext();
};

template <typename ContainerType, typename ValueType = ContainerType::value_type>
class IteratorImpl : public Iterator<ValueType> {
private:
    typedef typename ContainerType::iterator IteratorType;
    IteratorType it;
    IteratorType _end;
public:
    IteratorImpl(ContainerType &container)
        : it(container.begin()), _end(container.end()) {}
    IteratorImpl(IteratorType begin, IteratorType end) : it(begin), _end(end) {}

    ValueType next() { return (*it) ++; }
    bool hasNext() { return it != _end; }

    IteratorType begin() { return it; }
    IteratorType end() { return _end; }
};

template <typename ContainerType>
class IterableImpl {
private:
    typedef typename ContainerType::iterator IteratorType;
    ContainerType &container;
public:
    IterableImpl(ContainerType &container) : container(container) {}

    IteratorType begin() { return container.begin(); }
    IteratorType end() { return container.end(); }
};

template <typename Type, int InvalidInitializer = -1>
class ValueCache {
public:
    static const Type INVALID = static_cast<Type>(InvalidInitializer);
private:
    Type cache;
public:
    ValueCache() : cache(INVALID) {}

    Type get() const { return cache; }
    void set(Type value) { cache = value; }

    void invalidate() { cache = INVALID; }
    bool isValid() const { return cache != INVALID; }
};

class Position {
public:
    virtual ~Position() {}

    virtual address_t get() const = 0;
    virtual void set(address_t value) = 0;
};

class AbsolutePosition : public Position {
private:
    address_t address;
public:
    AbsolutePosition(address_t address) : address(address) {}

    virtual address_t get() const { return address; }
    virtual void set(address_t value) { this->address = value; }
};

class RelativePosition : public Position {
private:
    ChunkReference within;
    address_t offset;
public:
    RelativePosition(ChunkReference within) : within(within) {}

    virtual address_t get() const { return within->getParent()->getPosition() + offset; }
    virtual void set(address_t value) { offset = value - within->getParent()->getPosition(); }

    address_t getOffset() const { return offset; }
    void setOffset(address_t offset) { this->offset = offset; }
};

class CachedRelativePosition : protected RelativePosition {
private:
    mutable ValueCache<address_t> cache;
public:
    CachedRelativePosition(ChunkReference within) : RelativePosition(within) {}
    
    virtual address_t get() const
        { return cache.isValid() ? cache.get() : RelativePosition::get(); }
    virtual void set(address_t value) { RelativePosition::set(value); cache.set(value); }

    using RelativePosition::getOffset;
    void setOffset(address_t offset) { RelativePosition::setOffset(offset); cache.invalidate(); }

    void invalidateCache() { cache.invalidate(); }
};

class Size {
public:
    virtual ~Size() {}
    virtual size_t get() const = 0;
    virtual void adjustBy(size_t add) = 0;
};

class SummationSize {
private:
    size_t totalSize;
public:
    SummationSize() : totalSize(0) {}

    virtual size_t get() const;
    virtual void adjustBy(size_t add);

    void set(size_t value);
};

class Event {
private:
    Chunk *origin;
public:
    Event(Chunk *origin) : origin(origin) {}

    Chunk *getOrigin() const { return origin; }
};

class ResizeEvent : public Event {};
class MoveSourceEvent : public Event {};
class MoveTargetEvent : public Event {};
class AddLinkEvent : public Event {
private:
    Link *link;
public:
    Link *getLink() const { return link; }
};
class ReEncodeEvent : public Event {};

class EventListener {
public:
    virtual ~EventListener() {}
    virtual void handle(ResizeEvent e) {}
    virtual void handle(MoveSourceEvent e) {}
    virtual void handle(MoveTargetEvent e) {}
    virtual void handle(AddLinkEvent e) {}
    virtual void handle(ReEncodeEvent e) {}
};

class ChunkReference {
private:
    Chunk *ref;
public:
    ChunkReference(Chunk *ref = nullptr) : ref(ref) {}

    Chunk &operator * () const { return *ref; }
    operator bool() const { return ref != nullptr; }
};

class Link {
private:
    ChunkReference target;
public:
    LinkAttribute(ChunkReference target) : target(target) {}
    ChunkReference getTarget() const { return target; }
};

class XRef {
private:
    ChunkReference source;
    Link *link;
public:
    XRef(ChunkReference source, Link *link) : source(source), link(link) {}

    ChunkReference getSource() const { return source; }
    ChunkReference getTarget() const { return link->getTarget(); }
};

class XRefDatabase {
private:
    typedef std::vector<XRef> DatabaseType;
    DatabaseType database;
public:
    void add(XRef xref) { database.push_back(xref); }

    IterableImpl<DatabaseType> iterable()
        { return IterableImpl<DatabaseType>(database); }
};

class ChunkVisitor;

/** Chunks represent pieces of code arranged in a hierarchical structure.
    
    Some attributes are inherited from parents, such as relative positions.
    Other attributes are gathered from children, e.g. code sizes and links.

    Attributes:
*/
class Chunk : public EventListener {
public:
    virtual ~Chunk() {}

    virtual Chunk *getParent() const = 0;
    virtual Position *getPosition() const = 0;
    virtual Size *getSize() const = 0;

    virtual void accept(ChunkVisitor *visitor) { visitor.visit(this); }
};

class ChunkImpl : public Chunk {
private:
};

template <typename ChildType>
class CompositeChunkImpl : public CompositeChunk {
private:
    typedef std::vector<ChildType *> ChildListType;
    ChildListType childList;
public:
    IterableImpl<ChildType *> getChildren()
        { return IterableImpl<ChildType *>(childList); }
};

template <typename ChunkType>
class XRefDecorator : public ChunkType {
private:
    XRefDatabase database;
public:
    virtual void handle(AddLinkEvent e)
        { database.add(XRef(e.getOrigin(), e.getLink())); ChunkType::handle(e); }
};

class InstructionBase : public Chunk {
private:
    InstructionSemantic *semantic;
public:
    
};

class Function;
class Block;
class Instruction;
class InstructionSemantic;

class CodePage : public XRefDecorator<CompositeChunkImpl<Block>> {
};
class Function : public CompositeChunkImpl<Block> {
};
class Block : public CompositeChunkImpl<Instruction> {
};
class Instruction : public Chunk {
private:
    InstructionSemantic *semantic;
public:
};

class ChunkVisitor {
public:
    virtual ~ChunkVisitor() {}
    virtual void visit(CodePage *codePage) = 0;
    virtual void visit(Function *function) = 0;
    virtual void visit(Block *block) = 0;
    virtual void visit(Instruction *instruction) = 0;
};
class ChunkListener {
public:
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Function *function) {}
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
};
class ChunkDebugDisplay : public ChunkVisitor {};

/** Abstract base class for special instruction data.
*/
class InstructionSemantic {
public:
    virtual ~InstructionSemantic() {}
};

class UnprocessedInstruction : public InstructionSemantic {
private:
    std::string rawData;
public:
};
