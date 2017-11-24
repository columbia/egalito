#ifndef EGALITO_PASS_POPLUATEPLT_H
#define EGALITO_PASS_POPLUATEPLT_H

#include "chunkpass.h"

class PopulatePLTPass : public ChunkPass {
private:
    Conductor *conductor;
    Module *module;
public:
    PopulatePLTPass(Conductor *conductor) : conductor(conductor) {}
    virtual void visit(Module *module);
    virtual void visit(PLTTrampoline *trampoline);
private:
    void populateLazyTrampoline(PLTTrampoline *trampoline);
    void populateTrampoline(PLTTrampoline *trampoline);
};

#endif
