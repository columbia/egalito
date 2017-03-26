#ifndef EGALITO_PASS_RESOLVE_RELOCS_H
#define EGALITO_PASS_RESOLVE_RELOCS_H

#include "chunkpass.h"
#include "elf/reloc.h"
#include "chunk/plt.h"

class ResolveRelocs : public ChunkPass {
private:
    PLTList *pltList;
public:
    ResolveRelocs(PLTList *pltList) : pltList(pltList) {}
    virtual void visit(Instruction *instruction);
};

#endif
