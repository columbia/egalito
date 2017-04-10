#ifndef EGALITO_PASS_JUMP_TABLE_PASS_H
#define EGALITO_PASS_JUMP_TABLE_PASS_H

#include "chunkpass.h"

/** Constructs jump table data structures in the given Module. */
class JumpTablePass : public ChunkPass {
private:
    Module *module;
public:
    JumpTablePass(Module *module = nullptr) : module(module) {}
    virtual void visit(Module *module);
    virtual void visit(JumpTableList *jumpTableList);
};

#endif
