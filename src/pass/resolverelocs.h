#ifndef EGALITO_PASS_RESOLVE_RELOCS_H
#define EGALITO_PASS_RESOLVE_RELOCS_H

#include "chunkpass.h"
#include "elf/reloc.h"
#include "chunk/plt.h"

class ResolveRelocs : public ChunkPass {
private:
    PLTSection *pltSection;
public:
    ResolveRelocs(PLTSection *pltSection) : pltSection(pltSection) {}
    virtual void visit(Instruction *instruction);
};

#endif
