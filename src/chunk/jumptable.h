#ifndef EGALITO_CHUNK_JUMP_TABLE_H
#define EGALITO_CHUNK_JUMP_TABLE_H

#include "chunk.h"
#include "chunklist.h"

class JumpTableDescriptor;
class Function;
class ElfMap;

class JumpTableEntry : public ChunkImpl {
private:
    Link *link;
public:
    JumpTableEntry(Link *link) : link(link) {}

    Link *getLink() const { return link; }

    virtual void accept(ChunkVisitor *visitor);
};

class JumpTable : public CompositeChunkImpl<JumpTableEntry> {
private:
    JumpTableDescriptor *descriptor;
public:
    JumpTable(ElfMap *elf, JumpTableDescriptor *descriptor);

    Function *getFunction() const;
    long getEntryCount() const;  // returns -1 if not known
    JumpTableDescriptor *getDescriptor() const { return descriptor; }

    void makeChildren(ElfMap *elf);

    virtual void accept(ChunkVisitor *visitor);
};

class JumpTableList : public CompositeChunkImpl<JumpTable> {
public:
    virtual void setSize(size_t newSize) {}  // ignored
    virtual void addToSize(diff_t add) {}  // ignored
    virtual void accept(ChunkVisitor *visitor);
};

#endif
