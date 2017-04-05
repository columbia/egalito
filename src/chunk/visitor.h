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
    virtual void visit(PLTList *functionList) = 0;
    virtual void visit(Function *function) = 0;
    virtual void visit(Block *block) = 0;
    virtual void visit(Instruction *instruction) = 0;
    virtual void visit(PLTTrampoline *instruction) = 0;
};
class ChunkListener {
public:
    virtual void visit(Program *program) {}
    virtual void visit(Module *function) {}
    virtual void visit(FunctionList *functionList) {}
    virtual void visit(BlockSoup *functionList) {}
    virtual void visit(PLTList *functionList) {}
    virtual void visit(Function *function) {}
    virtual void visit(Block *block) {}
    virtual void visit(Instruction *instruction) {}
    virtual void visit(PLTTrampoline *instruction) {}
};

#endif
