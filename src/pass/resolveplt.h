#ifndef EGALITO_PASS_RESOLVE_PLT_H
#define EGALITO_PASS_RESOLVE_PLT_H

#include "chunkpass.h"

class Conductor;
class ElfSpace;

class ResolvePLTPass : public ChunkPass {
private:
    Program *program;
    Module *module;
public:
    ResolvePLTPass(Program *program)
        : program(program), module(nullptr) {}
    virtual void visit(Module *module);
protected:
    virtual void visit(PLTList *pltList);
    virtual void visit(PLTTrampoline *pltTrampoline);
};

#endif
