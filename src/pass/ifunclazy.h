#ifndef EGALITO_PASS_IFUNCLAZY_H
#define EGALITO_PASS_IFUNCLAZY_H

#include "chunkpass.h"

// relocation is not aware of the lazy selection

class IFuncList;

class IFuncLazyPass : public ChunkPass {
private:
    IFuncList *ifuncList;
    Module *module;
public:
    IFuncLazyPass(IFuncList *ifuncList) : ifuncList(ifuncList) {}
private:
    virtual void visit(Module *module);
    virtual void visit(PLTTrampoline *trampoline);
};

#endif
