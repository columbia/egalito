#ifndef EGALITO_CHUNK_H
#define EGALITO_CHUNK_H

#include <cstdint>
#include <vector>
#include <memory>  // for std::shared_ptr
#include "position.h"  // for Position
#include "size.h"  // for ComputedSize, Range
#include "link.h"  // for Link
#include "types.h"

class Sandbox;

class ChunkList;
template <typename ChildType>
class ChunkListImpl;

class ChunkVisitor;

/** Main base class for representing code and entities in a program.

    Chunks are arranged in a hierarchical structure. If the concrete type is
    known, it is possible to iterate over children in a type-safe manner.
    It is also possible to iterate over generic Chunks.

    Some Chunks have a Position, like Functions and Blocks and Instructions.
    Others, like JumpTableList, do not.
*/
class Chunk {
public:
    virtual ~Chunk() {}

    virtual std::string getName() const = 0;

    virtual Chunk *getParent() const = 0;
    virtual void setParent(Chunk *newParent) = 0;
    virtual Chunk *getPreviousSibling() const = 0;
    virtual void setPreviousSibling(Chunk *p) = 0;
    virtual Chunk *getNextSibling() const = 0;
    virtual void setNextSibling(Chunk *n) = 0;
    virtual ChunkList *getChildren() const = 0;

    virtual Position *getPosition() const = 0;
    virtual void setPosition(Position *newPosition) = 0;
    virtual size_t getSize() const = 0;
    virtual void setSize(size_t newSize) = 0;
    virtual void addToSize(diff_t add) = 0;

    virtual address_t getAddress() const = 0;
    virtual Range getRange() const = 0;

    virtual void accept(ChunkVisitor *visitor) = 0;
};

/** Main Chunk implementation class that provides parent and sibling links
    and sensible defaults for all functions. Use decorators to add additional
    functionality.
*/
class ChunkImpl : public Chunk {
private:
    Chunk *parent, *prev, *next;
public:
    ChunkImpl(Chunk *parent = nullptr)
        : parent(parent), prev(nullptr), next(nullptr) {}

    virtual std::string getName() const { return "???"; }

    virtual Chunk *getParent() const { return parent; }
    virtual void setParent(Chunk *newParent) { parent = newParent; }
    virtual Chunk *getPreviousSibling() const { return prev; }
    virtual void setPreviousSibling(Chunk *p) { prev = p; }
    virtual Chunk *getNextSibling() const { return next; }
    virtual void setNextSibling(Chunk *n) { next = n; }
    virtual ChunkList *getChildren() const { return nullptr; }

    virtual Position *getPosition() const { return nullptr; }
    virtual void setPosition(Position *newPosition);
    virtual size_t getSize() const { return 0; }
    virtual void setSize(size_t newSize);
    virtual void addToSize(diff_t add);

    virtual address_t getAddress() const;
    virtual Range getRange() const;
};

template <typename ChunkType>
class ChunkPositionDecorator : public ChunkType {
private:
    Position *position;
public:
    ChunkPositionDecorator(Position *position = nullptr)
        : position(position) {}

    virtual Position *getPosition() const { return position; }
    virtual void setPosition(Position *newPosition) { position = newPosition; }
};

template <typename ChunkType, typename ChildType>
class ChildListDecorator : public ChunkType {
public:
    typedef ChildType ChunkChildType;
private:
    mutable ChunkListImpl<ChildType> childList;
public:
    virtual ChunkListImpl<ChildType> *getChildren() const { return &childList; }
};

template <typename ChunkType>
class ComputedSizeDecorator : public ChunkType {
private:
    ComputedSize size;
public:
    virtual size_t getSize() const { return size.get(); }
    virtual void setSize(size_t newSize) { size.set(newSize); }
    virtual void addToSize(diff_t add) { size.adjustBy(add); }
};

/** Represents a leaf Chunk with a Position. */
typedef ChunkPositionDecorator<ChunkImpl> AddressableChunkImpl;

/** A Chunk that contains a list of other Chunks, and has a Position. */
template <typename ChildType>
class CompositeChunkImpl : public ChildListDecorator<
    ComputedSizeDecorator<AddressableChunkImpl>, ChildType> {
};

/** A Chunk that contains a list of other Chunks, but has no Position. */
template <typename ChildType>
class CollectionChunkImpl : public ChildListDecorator<ChunkImpl, ChildType> {
};

#endif
