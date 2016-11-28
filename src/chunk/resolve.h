#ifndef EGALITO_CHUNK_RESOLVE_H
#define EGALITO_CHUNK_RESOLVE_H

#include "chunk.h"
#include "concrete.h"

class ChunkResolver : public ChunkVisitor {
private:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->iterable()) {
            child->accept(this);
        }
    }
public:
    virtual void visit(Program *program) {}
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Function *function) { recurse(function); }
    virtual void visit(Block *block) { recurse(block); }
    virtual void visit(Instruction *instruction);
};

#endif
