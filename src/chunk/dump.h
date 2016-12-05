#ifndef EGALITO_CHUNK_DUMP_H
#define EGALITO_CHUNK_DUMP_H

#include "chunk.h"
#include "concrete.h"

class ChunkDumper : public ChunkVisitor {
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
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(Instruction *instruction);
};

#endif
