#ifndef EGALITO_PASS_REMOVEPADDING_H
#define EGALITO_PASS_REMOVEPADDING_H

#include "chunkpass.h"

class Module;
class FunctionList;
class Function;

class RemovePadding : public ChunkPass {
public:
    RemovePadding() {}
    virtual void visit(Module *module);
    virtual void visit(Function *function);
private:
    void removePadding(FunctionList *functionList);
};

#endif
