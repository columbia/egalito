#ifndef EGALITO_PASS_RESOLVE_RELOCS_H
#define EGALITO_PASS_RESOLVE_RELOCS_H

#include "chunkpass.h"
#include "elf/reloc.h"

class ResolveRelocs : public ChunkPass {
private:
    RelocList *relocList;
public:
    ResolveRelocs(RelocList *relocList) : relocList(relocList) {}
    virtual void visit(Instruction *instruction);
};

#endif
