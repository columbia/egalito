#ifndef EGALITO_CHUNK_VISITOR_H
#define EGALITO_CHUNK_VISITOR_H

#include "chunkfwd.h"

class ChunkVisitor {
public:
    virtual ~ChunkVisitor() {}
    virtual void visit(Program *program) = 0;
    virtual void visit(Module *function) = 0;
    virtual void visit(FunctionList *functionList) = 0;
    virtual void visit(BlockSoup *functionList) = 0;
    virtual void visit(PLTList *pltList) = 0;
    virtual void visit(JumpTableList *jumpTableList) = 0;
    virtual void visit(DataRegionList *dataRegionList) = 0;
    virtual void visit(Function *function) = 0;
    virtual void visit(Block *block) = 0;
    virtual void visit(Instruction *instruction) = 0;
    virtual void visit(PLTTrampoline *instruction) = 0;
    virtual void visit(JumpTable *jumpTable) = 0;
    virtual void visit(JumpTableEntry *jumpTableEntry) = 0;
    virtual void visit(DataRegion *dataRegion) = 0;
};
class ChunkListener {
public:
    virtual void visit(Program *program) {}
    virtual void visit(Module *function) {}
    virtual void visit(FunctionList *functionList) {}
    virtual void visit(BlockSoup *functionList) {}
    virtual void visit(PLTList *pltList) {}
    virtual void visit(JumpTableList *jumpTableList) {}
    virtual void visit(DataRegionList *dataRegionList) {}
    virtual void visit(Function *function) {}
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
    virtual void visit(PLTTrampoline *instruction) {}
    virtual void visit(JumpTable *jumpTable) {}
    virtual void visit(JumpTableEntry *jumpTableEntry) {}
    virtual void visit(DataRegion *dataRegion) {}
};

#endif
