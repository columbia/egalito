#ifndef EGALITO_PASS_PCRELATIVE_H
#define EGALITO_PASS_PCRELATIVE_H

#include "chunkpass.h"
#include "elf/reloc.h"

class Module;

// pick up any instruction (other than call) that have PC-relative
// immediates
class PCRelativePass : public ChunkPass {
private:
    ElfMap *elf;
public:
    PCRelativePass(ElfMap *elf) : elf(elf) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
};

#endif
