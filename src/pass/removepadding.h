#ifndef EGALITO_PASS_REMOVEPADDING_H
#define EGALITO_PASS_REMOVEPADDING_H

#include "chunkpass.h"

class Module;
class Function;

class RemovePadding : public ChunkPass {
private:
    std::vector<Function *> emptyFunctions;
public:
    RemovePadding() {}
    virtual void visit(Module *module);
    virtual void visit(Function *function);
private:
    void removeHead(Function *function);
    void removeTail(Function *function);
};

#endif
