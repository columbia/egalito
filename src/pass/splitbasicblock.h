#ifndef EGALITO_PASS_SPLIT_BASIC_BLOCK_H
#define EGALITO_PASS_SPLIT_BASIC_BLOCK_H

#include "chunkpass.h"
#include "elf/reloc.h"

class SplitBasicBlock : public ChunkPass {
public:
    SplitBasicBlock() {}
    virtual void visit(Function *function);
};

#endif
