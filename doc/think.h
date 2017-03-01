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
    virtual void set(size_t value) = 0;
    virtual void adjustBy(size_t add) = 0;
};

class SizeImpl : public Size {
public:
    virtual void adjustBy(size_t add) { set(get() + add); }
};

class FixedSize : public SizeImpl {
private:
    size_t size;
public:
    FixedSize(size_t size = 0) : size(size) {}
    virtual size_t get() const { return size; }
    virtual void set(size_t value) const { size = value; }
};

template <typename ChunkType>
class DelegatedSize : public SizeImpl {
private:
    ChunkType *within;
public:
    DelegatedSize(ChunkType *within) : within(within) {}

    virtual size_t get() const { return within->getSize(); }
    virtual void set(size_t value) { within->setSize(value); }
};

class SummationSize : public SizeImpl {
private:
    size_t totalSize;
public:
    SummationSize() : totalSize(0) {}

    virtual size_t get() const;
    virtual void set(size_t value);
    virtual void adjustBy(size_t add);
};

template <typename ChildType>
class ChunkList {
private:
    typedef std::vector<ChildType *> ChildListType;
    ChildListType childList;
public:
    virtual ~ChunkList() {}

    IterableImpl<ChildType *> iterable()
        { return IterableImpl<ChildType *>(childList); }

    virtual void add(ChildType *child) { childList.push_back(child); }
};

#if 0
template <typename ChildType>
class SearchableChunkList : public ChunkList<ChildType> {
private:
    typedef std::set<ChildType *> ChildSetType;
    ChildSetType childSet;
public:
    virtual void add(ChildType *child)
        { ChunkList<ChildType>::add(child); childSet.insert(child); }

    bool contains(ChildType *child)
        { return childSet.find(child) != childSet.end(); }
};
#endif

class Event {
public:
    enum EventType {
        EVENT_RESIZE,
        EVENT_MOVE_SOURCE,
        EVENT_MOVE_TARGET,
        EVENT_ADD_LINK,
        EVENT_RE_ENCODE,
        EVENTS
    };
private:
    Chunk *origin;
public:
    Event(Chunk *origin) : origin(origin) {}
    virtual ~Event() {}

    virtual EventType getType() const = 0;
    Chunk *getOrigin() const { return origin; }
};

class ResizeEvent : public Event {
public:
    virtual EventType getType() const { return EVENT_RESIZE; }
};
class MoveSourceEvent : public Event {
public:
    virtual EventType getType() const { return EVENT_MOVE_SOURCE; }
};
class MoveTargetEvent : public Event {
public:
    virtual EventType getType() const { return EVENT_MOVE_TARGET; }
};
class AddLinkEvent : public Event {
private:
    Link *link;
public:
    Link *getLink() const { return link; }
    virtual EventType getType() const { return EVENT_ADD_LINK; }
};
class ReEncodeEvent : public Event {
public:
    virtual EventType getType() const { return EVENT_RE_ENCODE; }
};

class EventObserver {
public:
    virtual ~EventListener() {}
    virtual void handle(ResizeEvent e) {}
    virtual void handle(MoveSourceEvent e) {}
    virtual void handle(MoveTargetEvent e) {}
    virtual void handle(AddLinkEvent e) {}
    virtual void handle(ReEncodeEvent e) {}
};

template <typename EventType>
class SingleEventObserver : public EventObserver {
public:
    virtual void handle(EventType e) = 0;
};

/** Stores a list of observers for each type for easy triggering. */
class EventObserverRegistry {
private:
    typedef std::vector<EventObserver *> ObserverList;
    typedef ObserverList ObserverMatrix[Event::EVENTS];
    ObserverMatrix registry;
public:
    template <typename EventType>
    void add(SingleEventObserver<EventType> observer) { registry[EventType].push_back(observer); }
    void add(EventObserver *observer, Event::EventType type) { registry[type].push_back(observer); }
    void addToAll(EventObserver *observer);

    template <typename EventType>
    void remove(SingleEventObserver<EventType> observer);
    void remove(EventObserver *observer, Event::EventType type);
    void removeFromAll(EventObserver *observer);

    void fire(Event *event) { for(auto obs : registry[event->getType()]) { obs.handle(*event); } }
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
    Link(ChunkReference target) : target(target) {}
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
*/
class Chunk {
public:
    virtual ~Chunk() {}

    virtual EventObserverRegistry *getRegistry() const = 0;

    virtual Chunk *getParent() const = 0;
    virtual ChunkList<Chunk *> *getChildren() const = 0;
    virtual Position *getPosition() const = 0;
    virtual Size *getSize() const = 0;
    virtual XRefDatabase *getDatabase() const = 0;

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
    virtual EventObserverRegistry *getRegistry() const { return &registry; }

    virtual Chunk *getParent() const { return parent; }
    virtual ChunkList<Chunk *> *getChildren() const { return nullptr; }
    virtual Position *getPosition() const { return position; }
    virtual Size *getSize() const { return nullptr; }
    virtual XRefDatabase *getDatabase() const { return nullptr; }
};

template <typename ChunkType, typename ChildType>
class ChildListDecorator : public ChunkType {
private:
    ChunkList<ChildType> childList;
public:
    virtual ChunkList<ChildType *> *getChildren() const { return &childList; }
};

template <typename ChunkType>
class SummationSizeDecorator : public ChunkType {
private:
    SummationSize size;
public:
    virtual Size *getSize() const { return &size; }
};

template <typename ChildType>
class CompositeChunkImpl : public ChildListDecorator<SummationSizeDecorator<ChunkImpl>, ChildType> {
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

class Function;
class Block;
class Instruction;
class InstructionSemantic;

class Program : public ChunkImpl {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor.visit(this); }
};
class CodePage : public XRefDecorator<CompositeChunkImpl<Block>> {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor.visit(this); }
};
class Function : public CompositeChunkImpl<Block> {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor.visit(this); }
};
class Block : public CompositeChunkImpl<Instruction> {
public:
    virtual void accept(ChunkVisitor *visitor) { visitor.visit(this); }
};
class Instruction : public ChunkImpl {
private:
    InstructionSemantic *semantic;
    DelegatedSize<InstructionSemantic> delegatedSize;
public:
    Instruction(InstructionSemantic *semantic)
        : semantic(semantic), delegatedSize(semantic) {}

    void setSemantic(InstructionSemantic *semantic);

    virtual Size *getSize() { return &delegatedSize; }

    virtual void accept(ChunkVisitor *visitor) { visitor.visit(this); }
};

class ChunkFactory {
public:
    Program *makeProgram();
    CodePage *makeCodePage();
    Function *makeFunction();
    Block *makeBlock();
    Instruction *makeInstruction(InstructionSemantic *semantic);
};

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
class ChunkDebugDisplay : public ChunkVisitor {};

class SemanticVisitor;

/** Abstract base class for special instruction data.
*/
class InstructionSemantic {
public:
    virtual ~InstructionSemantic() {}

    virtual size_t getSize() const = 0;
    virtual void setSize(size_t value) = 0;

    virtual void accept(SemanticVisitor *visitor) = 0;
};

class SemanticImpl : public InstructionSemantic {
private:

public:
    virtual size_t setSize(size_t value);
};

class UnprocessedInstruction : public InstructionSemantic {
private:
    std::string rawData;
public:
    virtual size_t getSize() const { return rawData.size(); }

    virtual void accept(SemanticVisitor *visitor) { visitor->visit(this); }
};
class NormalSemanticImpl : public SemanticImpl {
private:
    cs_insn insn;
public:
    NormalSemanticImpl(const cs_insn &insn) : insn(insn) {}

    virtual size_t getSize() const { return insn.size; }

    uint8_t *getBytes() const { return insn.bytes; }
};

class ControlFlowInstruction : public InstructionSemantic {
private:
    std::string opcode;
    int displacementSize;
    Link *target;
public:
    ControlFlowInstruction() : target(nullptr) {}
    ControlFlowInstruction(Link *target) : target(target) {}

    virtual size_t getSize() const { return opcode.size() + displacementSize; }

    virtual void accept(SemanticVisitor *visitor) { visitor->visit(this); }
};

class SemanticVisitor {
public:
    virtual ~SemanticVisitor() {}
    virtual void visit(UnprocessedInstruction *semantic) = 0;
    virtual void visit(ControlFlowInstruction *semantic) = 0;
};
