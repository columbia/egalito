#ifndef EGALITO_PASS_PCRELATIVE_H
#define EGALITO_PASS_PCRELATIVE_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

// For -q binaries,
// pick up any instruction that have PC-relative data access.
// Function pointers should be resolved before running this pass.
class PCRelativePass : public ChunkPass {
private:
    Module *module;
    RelocList *relocList;
public:
    PCRelativePass(RelocList *relocList) : relocList(relocList) {}
    virtual void visit(Module *module);
private:
    virtual void handlePCRelative(Reloc *r, FunctionList *functionList);
};

#endif
