#ifndef EGALITO_PASS_RELOCHECK_H
#define EGALITO_PASS_RELOCHECK_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

class ReloCheckPass : public ChunkPass {
public:
    virtual void visit(Module *module);
private:
    void check(Reloc *r, Module *module);
};

#endif
