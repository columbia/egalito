#ifndef EGALITO_PASS_PCRDATA_H
#define EGALITO_PASS_PCRDATA_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

class PCRDataPass : public ChunkPass {
private:
public:
    PCRDataPass() {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
