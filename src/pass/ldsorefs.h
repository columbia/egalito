#ifndef EGALITO_PASS_LDSOREFS_H
#define EGALITO_PASS_LDSOREFS_H

#include "chunkpass.h"

class LdsoRefsPass : public ChunkPass {
private:
    Function *emptyTarget;
public:
    LdsoRefsPass() : emptyTarget(nullptr) {}
    
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Instruction *instruction);
};

#endif
