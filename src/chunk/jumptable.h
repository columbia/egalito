#ifndef EGALITO_CHUNK_JUMP_TABLE_H
#define EGALITO_CHUNK_JUMP_TABLE_H

#include "chunk.h"
#include "chunklist.h"

class JumpTableDescriptor;
class Function;
class ElfMap;

class JumpTableEntry : public AddressableChunkImpl {
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

    void setDescriptor(JumpTableDescriptor *descriptor)
        { this->descriptor = descriptor; }

    virtual void accept(ChunkVisitor *visitor);
};

class JumpTableList : public CollectionChunkImpl<JumpTable> {
public:
    virtual void accept(ChunkVisitor *visitor);
};

#endif
