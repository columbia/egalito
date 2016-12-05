#ifndef EGALITO_CHUNK_RESOLVE_H
#define EGALITO_CHUNK_RESOLVE_H

#include "chunk.h"
#include "concrete.h"
#include "chunklist.h"

class ChunkResolver : public ChunkVisitor {
private:
    SpatialChunkList<Function, ChunkList> functionList;
private:
    template <typename Type>
    void recurse(Type *root) {
        for(auto child : root->getChildren()->iterable()) {
            child->accept(this);
        }
    }
public:
    ChunkResolver(std::vector<Function *> &flist);
    virtual void visit(Program *program) {}
    virtual void visit(CodePage *codePage) {}
    virtual void visit(Module *module) { recurse(module); }
    virtual void visit(Function *function) { recurse(function); }
    virtual void visit(Block *block) { recurse(block); }
    virtual void visit(Instruction *instruction);
private:
    template <typename ChunkType>
    Chunk *find(ChunkType *root, address_t targetAddress);
    template <typename ChunkType>
    Chunk *findHelper(ChunkType *root, address_t targetAddress);
};

#endif
