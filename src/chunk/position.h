#ifndef EGALITO_POSITION_H
#define EGALITO_POSITION_H

#include "chunkref.h"
#include "types.h"

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
    ChunkRef object;
    address_t offset;
public:
    RelativePosition(ChunkRef object) : object(object) {}

    virtual address_t get() const;
    virtual void set(address_t value);

    address_t getOffset() const { return offset; }
    void setOffset(address_t offset) { this->offset = offset; }
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

class CachedRelativePosition : protected RelativePosition {
private:
    mutable ValueCache<address_t> cache;
public:
    CachedRelativePosition(ChunkRef object) : RelativePosition(object) {}

    virtual address_t get() const;
    virtual void set(address_t value);

    using RelativePosition::getOffset;
    void setOffset(address_t offset);

    void invalidateCache() { cache.invalidate(); }
};

class ComputedSize {
private:
    size_t size;
public:
    ComputedSize() : size(0) {}
    size_t get() const { return size; }
    void set(size_t newSize) { size = newSize; }
    void adjustBy(diff_t add);
};

#if 0
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
    virtual void set(size_t value) { size = value; }
};

template <typename ChunkType>
class DelegatedSize : public SizeImpl {
private:
    ChunkType *object;
public:
    DelegatedSize(ChunkType *object) : object(object) {}

    virtual size_t get() const { return object->getSize(); }
    virtual void set(size_t value) { object->setSize(value); }
};

class CompositeSize : public SizeImpl {
private:
    size_t totalSize;
public:
    CompositeSize() : totalSize(0) {}

    virtual size_t get() const { return totalSize; }
    virtual void set(size_t value) { totalSize = value; }
    virtual void adjustBy(size_t add);
};
#endif

#if 0
class CodeLink {
public:
    address_t getSourceAddress() const;
    address_t getTargetAddress() const;
};

template <typename SourcePosition>
class KnownSourceLink {
private:
    SourcePosition source;
    Position *target;
public:
    KnownSourceLink(SourcePosition source, Position *target)
        : source(source), target(target) {}
    address_t getSourceAddress() const { return source.get(); }
    address_t getTargetAddress() const { return target->get(); }
    SourcePosition *getSource() { return &source; }
    Position *getTarget() { return target; }
    void setTarget(Position *position) { target = position; }
};
#endif

#endif
