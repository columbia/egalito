#include <cstring>
#include <cstdint>
#include <fstream>
#include "serialize.h"
#include "chunk.h"
#include "concrete.h"
#include "visitor.h"
#include "archive/writer.h"
#include "archive/flatchunk.h"

class SerializeImpl : public ChunkListener {
private:
    EgalitoArchiveWriter &archive;
public:
    SerializeImpl(EgalitoArchiveWriter &archive) : archive(archive) {}
    virtual void visit(Program *program);
    virtual void visit(Module *function);
    //virtual void visit(FunctionList *functionList);
    //virtual void visit(PLTList *pltList);
    //virtual void visit(JumpTableList *jumpTableList);
    //virtual void visit(DataRegionList *dataRegionList);
    //virtual void visit(Function *function);
    //virtual void visit(Block *block);
    //virtual void visit(Instruction *instruction);
    //virtual void visit(PLTTrampoline *instruction);
    //virtual void visit(JumpTable *jumpTable);
    //virtual void visit(JumpTableEntry *jumpTableEntry);
    //virtual void visit(DataRegion *dataRegion);
};

void SerializeImpl::visit(Program *program) {
    archive.getFlatList().newFlatChunk(FlatChunk(0, 0, 0));
    archive.getFlatList().append32(program->getChildren()
        ->getIterable()->getCount());

    for(auto module : CIter::children(program)) {
        module->accept(this);
    }
}

void SerializeImpl::visit(Module *function) {
    
}

void ChunkSerializer::serialize(Chunk *chunk, std::string filename) {
    EgalitoArchiveWriter archive;
    SerializeImpl serializer(archive);
    chunk->accept(&serializer);

    archive.writeTo(filename);
}

Chunk *ChunkSerializer::deserialize(std::string filename) {
    Chunk *root = nullptr;

    return root;
}
