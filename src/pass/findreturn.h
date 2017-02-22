#ifndef EGALITO_PASS_FINDRETURN_H
#define EGALITO_PASS_FINDRETURN_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

// pick up return from function or exception
class FindReturnPass : public ChunkPass {
private:
    ElfMap *elf;
public:
    FindReturnPass() {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
