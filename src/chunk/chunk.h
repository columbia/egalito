#ifndef EGALITO_CHUNK_H
#define EGALITO_CHUNK_H

#include <cstdint>
#include <vector>
#include <memory>  // for std::shared_ptr
#include "elf/symbol.h"
#include "position.h"  // for Position
#include "size.h"  // for ComputedSize, Range
#include "link.h"  // for Link, XRefDatabase
#include "types.h"

class Sandbox;

class ChunkList;
template <typename ChildType>
class ChunkListImpl;

class ChunkVisitor;

/** Chunks represent pieces of code arranged in a hierarchical structure.
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
    virtual XRefDatabase *getDatabase() const = 0;

    virtual address_t getAddress() const = 0;
    virtual Range getRange() const = 0;

    virtual void accept(ChunkVisitor *visitor) = 0;
};

class ChunkImpl : public Chunk {
private:
    Chunk *parent, *prev, *next;
    Position *position;
public:
    ChunkImpl(Chunk *parent = nullptr, Position *position = nullptr)
        : parent(parent), prev(nullptr), next(nullptr), position(position) {}

    virtual std::string getName() const { return "???"; }

    virtual Chunk *getParent() const { return parent; }
    virtual void setParent(Chunk *newParent) { parent = newParent; }
    virtual Chunk *getPreviousSibling() const { return prev; }
    virtual void setPreviousSibling(Chunk *p) { prev = p; }
    virtual Chunk *getNextSibling() const { return next; }
    virtual void setNextSibling(Chunk *n) { next = n; }
    virtual ChunkList *getChildren() const { return nullptr; }

    virtual Position *getPosition() const { return position; }
    virtual void setPosition(Position *newPosition) { position = newPosition; }
    virtual size_t getSize() const { return 0; }
    virtual void setSize(size_t newSize);
    virtual void addToSize(diff_t add);
    virtual XRefDatabase *getDatabase() const { return nullptr; }

    virtual address_t getAddress() const;
    virtual Range getRange() const;

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

template <typename ChildType>
class CompositeChunkImpl : public ChildListDecorator<
    ComputedSizeDecorator<ChunkImpl>, ChildType> {
};

#if 0
template <typename ChunkType>
class XRefDecorator : public ChunkType {
private:
    XRefDatabase database;
public:
    virtual XRefDatabase *getDatabase() const { return &database; }

    virtual void handle(AddLinkEvent e)
        { database.add(XRef(e.getOrigin(), e.getLink())); ChunkType::handle(e); }
};
#endif

#endif
