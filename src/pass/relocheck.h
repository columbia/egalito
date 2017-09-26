#ifndef EGALITO_PASS_RELOCHECK_H
#define EGALITO_PASS_RELOCHECK_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;
class Instruction;

class ReloCheckPass : public ChunkPass {
public:
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
private:
    void check(Reloc *r, Module *module);
    void checkDataVariable(Module *module);
};

#endif
