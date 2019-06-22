#ifndef EGALITO_CHUNK_JUMP_TABLE_H
#define EGALITO_CHUNK_JUMP_TABLE_H

#include "chunk.h"
#include "chunklist.h"
#include "archive/chunktypes.h"

class DataVariable;
class JumpTableDescriptor;
class Function;
class Instruction;

class JumpTableEntry : public ChunkSerializerImpl<TYPE_JumpTableEntry,
    AddressableChunkImpl> {
private:
    DataVariable *dataVariable;
public:
    JumpTableEntry(DataVariable *dataVariable = nullptr) : dataVariable(dataVariable) {}

    DataVariable *getDataVariable() const { return dataVariable; }
    void setDataVariable(DataVariable *dataVariable)
        { this->dataVariable = dataVariable; }

    Link *getLink() const;
    void setLink(Link *link);

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

/** Assembly-level jump table chunk. Contains a list of JumpTableEntry's as
    children. Also stores a list of indirect jumps that reference this table.

    If the jump table could not be fully analyzed, getEntryCount() will return
    -1 and there will be no JumpTableEntry children.
*/
class JumpTable : public ChunkSerializerImpl<TYPE_JumpTable,
    CompositeChunkImpl<JumpTableEntry>> {
private:
    JumpTableDescriptor *descriptor;
    std::vector<Instruction *> jumpInstrList;
public:
    JumpTable() : descriptor(nullptr) {}
    JumpTable(JumpTableDescriptor *descriptor);

    Function *getFunction() const;
    std::vector<Instruction *> getJumpInstructionList() const;
    long getEntryCount() const;  // returns -1 if not known
    JumpTableDescriptor *getDescriptor() const { return descriptor; }

    void setDescriptor(JumpTableDescriptor *descriptor)
        { this->descriptor = descriptor; }
    void addJumpInstruction(Instruction *instr);

    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual void accept(ChunkVisitor *visitor);
};

class JumpTableList : public ChunkSerializerImpl<TYPE_JumpTableList,
    CollectionChunkImpl<JumpTable>> {
public:
    virtual void serialize(ChunkSerializerOperations &op,
        ArchiveStreamWriter &writer);
    virtual bool deserialize(ChunkSerializerOperations &op,
        ArchiveStreamReader &reader);

    virtual std::string getName() const { return "jumptablelist"; }
    virtual void accept(ChunkVisitor *visitor);
};

#endif
