#ifndef EGALITO_PASS_BASIC_BLOCK_COUNT_PASS_H
#define EGALITO_PASS_BASIC_BLOCK_COUNT_PASS_H

#include "chunkpass.h"

class Symbol;

/* Counts the number of basic blocks in the target module */
class BasicBlockCountPass : public ChunkPass {
private:
    const char *bbCountSymbolName;
    Symbol *counterSymbol;
    Module *module;
public:
    BasicBlockCountPass() : bbCountSymbolName("my_basic_block_counter") {}
    virtual void visit(Module *block);
    virtual void visit(Block *block);
};

#endif
