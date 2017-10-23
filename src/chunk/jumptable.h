#ifndef EGALITO_CHUNK_JUMP_TABLE_H
#define EGALITO_CHUNK_JUMP_TABLE_H

#include "chunk.h"
#include "chunklist.h"

class JumpTableDescriptor;
class Function;
class Instruction;
class ElfMap;

class JumpTableEntry : public AddressableChunkImpl {
private:
    Link *link;
public:
    JumpTableEntry(Link *link) : link(link) {}

    Link *getLink() const { return link; }

    virtual void accept(ChunkVisitor *visitor);
};

/** Assembly-level jump table chunk. Contains a list of JumpTableEntry's as
    children. Also stores a list of indirect jumps that reference this table.

    If the jump table could not be fully analyzed, getEntryCount() will return
    -1 and there will be no JumpTableEntry children.
*/
class JumpTable : public CompositeChunkImpl<JumpTableEntry> {
private:
    JumpTableDescriptor *descriptor;
    std::vector<Instruction *> jumpInstrList;
public:
    JumpTable(ElfMap *elf, JumpTableDescriptor *descriptor);

    Function *getFunction() const;
    std::vector<Instruction *> getJumpInstructionList() const;
    long getEntryCount() const;  // returns -1 if not known
    JumpTableDescriptor *getDescriptor() const { return descriptor; }

    void setDescriptor(JumpTableDescriptor *descriptor)
        { this->descriptor = descriptor; }
    void addJumpInstruction(Instruction *instr);

    virtual void accept(ChunkVisitor *visitor);
};

class JumpTableList : public CollectionChunkImpl<JumpTable> {
public:
    virtual void accept(ChunkVisitor *visitor);
};

#endif
