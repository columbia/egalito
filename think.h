#include <string>
#include "types.h"

class Chunk;
class ChunkReference;

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
    ValueCache<address_t> cache;
public:
    RelativePosition(ChunkReference within) : within(within) {}

    virtual address_t get() const
        { return cache.isValid() ? cache.get() : within->getParent()->getPosition() + offset; }
    virtual void set(address_t value) { offset = value - within->getParent()->getPosition(); cache.set(value); }

    address_t getOffset() const { return offset; }
    void setOffset(address_t offset) { this->offset = offset; }
};

class Size {
public:
    virtual ~Size() {}
    virtual size_t get() = 0;
};

class SummationSize {
private:
    ValueCache<size_t> cachedSize;
public:
    virtual size_t get();

    void compute(CompositeChunk *list);
    void invalidate() { cachedSize.invalidate(); }
};

class Extent {
public:
    virtual Position *getPosition() const = 0;
    virtual size_t getSize() const = 0;

    virtual void finalize();
};

class Event {
private:
    Chunk *origin;
public:
    Event(Chunk *origin) : origin(origin) {}
};

class ResizeEvent : public Event {};
class MoveSourceEvent : public Event {};
class MoveTargetEvent : public Event {};
class ReEncodeEvent : public Event {};

class ChunkReference {
private:
    Chunk *ref;
public:
    ChunkReference(Chunk *ref = nullptr) : ref(ref) {}

    Chunk &operator * () const { return *ref; }
    operator bool() const { return ref != nullptr; }
};

class LinkAttribute {
private:
    ChunkReference source, target;
public:
    LinkAttribute(ChunkReference source, ChunkReference target)
        : source(source), target(target) {}
    ChunkReference getSource() const { return source; }
    ChunkReference getTarget() const { return target; }
};

/** Chunks represent pieces of code arranged in a hierarchical structure.
    
    Some attributes are inherited from parents, such as relative positions.
    Other attributes are gathered from children, e.g. code sizes and links.

    Attributes:
*/
class Chunk {
public:
    class Iterator {
    public:
        bool hasNext();
        Chunk *next();
    };
private:
    NamedEntity name;
    Position *position;
public:
    virtual ~Chunk() {}

    virtual Chunk *getParent() const = 0;
    virtual void invalidateSize() = 0;
};

class CompositeChunk : public Chunk {
private:
    typedef std::vector<Chunk *> ChildListType;
public:
    class IteratorImpl : public Iterator {
    private:
        CompositeChunk *outer;
        typename ChildListType::iterator i;
    public:
        IteratorImpl(CompositeChunk *outer) : i(outer->begin()) {}
        bool hasNext() { return *i == outer->end(); }
        Chunk *next() { return (*i)++; }
    };
protected:
    typename ChildListType::iterator begin() { return childList.begin(); }
    typename ChildListType::iterator end() { return childList.end(); }
public:

};

template <typename ChildType>
class CompositeChunkImpl : public CompositeChunk {
private:
    typedef std::vector<ChildType *> ChildListType;
public:
    typename ChildListType::iterator begin() { return childList.begin(); }
    typename ChildListType::iterator end() { return childList.end(); }
};

class Function;
class Block;
class Instruction;
class InstructionSemantic;

class CodePage : public CompositeChunkImpl<Block> {
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
