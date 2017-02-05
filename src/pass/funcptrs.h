#ifndef EGALITO_PASS_FUNCPTRS_H
#define EGALITO_PASS_FUNCPTRS_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

class FuncptrsPass : public ChunkPass {
private:
    RelocList *relocList;
public:
    FuncptrsPass(RelocList *relocList) : relocList(relocList) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction) {}
private:
    void handleRelocation(Reloc *r, Module *module, Function *target);
};

#endif
