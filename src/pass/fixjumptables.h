#ifndef EGALITO_PASS_FIX_JUMP_TABLES_H
#define EGALITO_PASS_FIX_JUMP_TABLES_H

#include "chunkpass.h"

class FixJumpTablesPass : public ChunkPass {
private:
    Module *module;
public:
    FixJumpTablesPass(Module *module = nullptr) : module(module) {}

    virtual void visit(Module *module);
    virtual void visit(JumpTableList *jumpTableList);
    virtual void visit(JumpTable *jumpTable);
};

#endif
