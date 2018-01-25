#ifndef EGALITO_PASS_REORDER_PUSH_H
#define EGALITO_PASS_REORDER_PUSH_H

#include <vector>
#include "chunkpass.h"

class Module;
class Function;

class ReorderPush : public ChunkPass {
private:
    std::vector<int> pushOrder;
public:
    virtual void visit(Module *module);
    virtual void visit(Function *function);
private:
    Instruction *pickNextInstruction(std::vector<Instruction *> list,
        bool recordPushes, bool enforcePops);
};

#endif
