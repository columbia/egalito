#ifndef EGALITO_PASS_CHECKPASS_H
#define EGALITO_PASS_CHECKPASS_H

#include "pass/chunkpass.h"

class EncodingCheckPass : public ChunkPass {
private:
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
