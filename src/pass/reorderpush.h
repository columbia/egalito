#ifndef EGALITO_PASS_REORDER_PUSH_H
#define EGALITO_PASS_REORDER_PUSH_H

#include "chunkpass.h"

class Module;
class Function;

class ReorderPush : public ChunkPass {
public:
    virtual void visit(Module *module);
    virtual void visit(Function *function);
private:
    Instruction *pickNextInstruction(const std::vector<Instruction *> &list);
};

#endif
