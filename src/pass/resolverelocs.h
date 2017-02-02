#ifndef EGALITO_PASS_RESOLVE_RELOCS_H
#define EGALITO_PASS_RESOLVE_RELOCS_H

#include "chunkpass.h"
#include "elf/reloc.h"
#include "chunk/plt.h"

class ResolveRelocs : public ChunkPass {
private:
    RelocList *relocList;
    PLTRegistry pltRegistry;
public:
    ResolveRelocs(RelocList *relocList)
        : relocList(relocList) { buildRegistry(); }
    virtual void visit(Instruction *instruction);
private:
    void buildRegistry();
};

#endif
