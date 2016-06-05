#ifndef EGALITO_POSITION_H
#define EGALITO_POSITION_H

#include "types.h"

class Chunk;

class Position {
public:
    virtual ~Position() {}

    virtual address_t get() const = 0;
    virtual void set(address_t value) = 0;

    virtual void finalize() {}
};

template <typename Type>
class FixedValue {
private:
    Type value;
public:
    FixedValue(Type value) : value(value) {}

    Type get() const { return value; }
    void set(const Type &newValue)
        { throw "Can't set FixedValue!"; }
};

template <typename Type>
class MemoryValue {
private:
    Type previous;
    Type proposed;
public:
    MemoryValue(Type value) : previous(value), proposed(value) {}

    Type get() const { return proposed; }
    void set(const Type &newValue) { this->proposed = newValue; }

    Type getDelta() const { return proposed - previous; }
    void finalize() { previous = proposed; }
};

class NormalPosition : public Position, public MemoryValue<address_t> {
public:
    NormalPosition(address_t address) : MemoryValue<address_t>(address) {}

    virtual address_t get() const
        { return MemoryValue<address_t>::get(); }
    virtual void set(address_t value)
        { MemoryValue<address_t>::set(value); }
    using MemoryValue<address_t>::getDelta;
    using MemoryValue<address_t>::finalize;
};

class RelativePosition : public Position {
private:
    MemoryValue<address_t> offset;
    Chunk *relativeTo;
public:
    RelativePosition(Chunk *relativeTo, address_t offset)
        : offset(offset), relativeTo(relativeTo) {}

    virtual address_t get() const;
    virtual void set(address_t value);

    address_t getOffset() const { return offset.get(); }
    void setOffset(address_t value) { offset.set(value); }

    virtual void finalize();
};

class OriginalPosition : public Position, public FixedValue<address_t> {
public:
    OriginalPosition(address_t address) : FixedValue<address_t>(address) {}

    virtual address_t get() const
        { return FixedValue<address_t>::get(); }
    virtual void set(address_t value)
        { FixedValue<address_t>::set(value); }
};

class Size {
private:
    size_t value;
    Chunk *within;
};

class SimpleSize : public FixedValue<size_t> {
public:
    SimpleSize(size_t size) : FixedValue<size_t>(size) {}

    using FixedValue<size_t>::get;
    using FixedValue<size_t>::set;
};

class CalculatedSize {
private:
    size_t cache;
    bool valid;
public:
    CalculatedSize(size_t size, bool valid = true)
        : cache(size), valid(valid) {}

    size_t get() const;
    void set(size_t size) { cache = size, valid = true; }
    void add(size_t a) { cache += a; }

    bool isValid() const { return valid; }
    void invalidate() { valid = false; }
};

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

#if 0
class Position {
private:
    /** Original address as it appeared in the ELF file. */
    address_t original;

    /** Address currently encoded in instruction opcodes. */
    address_t current;

    /** The new address that will soon be used. */
    address_t assigned;

    /** If non-NULL, then addresses are relative to this as a base address. */
    Chunk *relativeTo;
public:
    Position(address_t original)
        : original(original), current(original), assigned(original),
        relativeTo(nullptr) {}
    Position(address_t original, address_t current, Chunk *relativeTo = nullptr)
        : original(original), current(current), assigned(assigned),
        relativeTo(relativeTo) {}

    void assign(address_t to) { assigned = to; }
    void resolve(Chunk *relativeTo, bool makeRelative = false);
    void finalize() { current = assigned; }

    address_t getAssignment() const { return assigned; }
    address_t getOriginalDelta() const { return assigned - original; }
    address_t getDelta() const { return assigned - current; }
};

class CodeLink {
private:
    Position source;
    Position target;
public:
    address_t getSourceAddress() const { return source.get(); }
    address_t getTargetAddress() const { return target.get(); }
    Position &getSource() { return source; }
    Position &getTarget() { return target; }
};
#endif

#endif
