#ifndef EGALITO_PASS_CHUNK_PASS_H
#define EGALITO_PASS_CHUNK_PASS_H

#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "chunk/chunklist.h"

class ChunkPass : public ChunkVisitor {
protected:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->genericIterable()) {
            child->accept(this);
        }
    }
public:
    virtual void visit(Program *program) {}
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Module *module) { recurse(module); }
    virtual void visit(Function *function) { recurse(function); }
    virtual void visit(Block *block) { recurse(block); }
    virtual void visit(Instruction *instruction) = 0;
};

#endif
