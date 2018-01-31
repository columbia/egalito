#ifndef EGALITO_PASS_DUMPLINK_H
#define EGALITO_PASS_DUMPLINK_H

#include "chunkpass.h"

class DumpLinkPass : public ChunkPass {
private:
    address_t mapbase;
public:
    virtual void visit(Module *module);
private:
    virtual void visit(Instruction *instruction);
    void dump(Reloc *reloc, Module *module);
    void output(address_t source, Link *link);
};

#endif
