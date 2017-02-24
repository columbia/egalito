#ifndef EGALITO_PASS_CONTROLFLOW_H
#define EGALITO_PASS_CONTROLFLOW_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

// detect controlflow instructions
class ControlFlowPass : public ChunkPass {
private:
    ElfMap *elf;
public:
    ControlFlowPass(ElfMap *elf) : elf(elf) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
