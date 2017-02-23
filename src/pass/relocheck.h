#ifndef EGALITO_PASS_RELOCHECK_H
#define EGALITO_PASS_RELOCHECK_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

class ReloCheckPass : public ChunkPass {
private:
    RelocList *relocList;
public:
    ReloCheckPass(RelocList *relocList) : relocList(relocList) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction) {}
private:
    void checkSemantic(Reloc *r, Module *module);
};

#endif
