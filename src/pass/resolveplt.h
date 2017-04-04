#ifndef EGALITO_PASS_RESOLVE_PLT_H
#define EGALITO_PASS_RESOLVE_PLT_H

#include "chunkpass.h"

class Conductor;
class ElfSpace;

class ResolvePLTPass : public ChunkPass {
private:
    Conductor *conductor;
    ElfSpace *elfSpace;
public:
    ResolvePLTPass(Conductor *conductor, ElfSpace *elfSpace)
        : conductor(conductor), elfSpace(elfSpace) {}
    virtual void visit(PLTList *pltList);
    virtual void visit(PLTTrampoline *pltTrampoline);
    virtual void visit(Instruction *instruction) {}
};

#endif
