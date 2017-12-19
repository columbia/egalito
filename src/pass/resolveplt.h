#ifndef EGALITO_PASS_RESOLVE_PLT_H
#define EGALITO_PASS_RESOLVE_PLT_H

#include "chunkpass.h"

class Conductor;
class ElfSpace;

class ResolvePLTPass : public ChunkPass {
private:
    Conductor *conductor;
    Module *module;
public:
    ResolvePLTPass(Conductor *conductor)
        : conductor(conductor), module(nullptr) {}
protected:
    virtual void visit(Module *module);
    virtual void visit(PLTList *pltList);
    virtual void visit(PLTTrampoline *pltTrampoline);
};

#endif
