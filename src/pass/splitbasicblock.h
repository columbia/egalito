#ifndef EGALITO_PASS_SPLIT_BASIC_BLOCK_H
#define EGALITO_PASS_SPLIT_BASIC_BLOCK_H

#include <set>
#include "chunkpass.h"
#include "elf/reloc.h"

class SplitBasicBlock : public ChunkPass {
private:
    std::set<Instruction *> splitPoints;
public:
    SplitBasicBlock() {}
    virtual void visit(Function *function);
private:
    void considerSplittingFor(Function *function, NormalLink *link);
};

#endif
