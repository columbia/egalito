#ifndef EGALITO_PASS_COLLAPSE_PLT_H
#define EGALITO_PASS_COLLAPSE_PLT_H

#include "chunkpass.h"

class CollapsePLTPass : public ChunkPass {
public:
    virtual void visit(Instruction *instr);
};

#endif
