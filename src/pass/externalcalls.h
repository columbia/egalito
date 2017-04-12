#ifndef EGALITO_PASS_EXTERNAL_CALLS_H
#define EGALITO_PASS_EXTERNAL_CALLS_H

#include "chunkpass.h"
#include "elf/reloc.h"
#include "chunk/plt.h"

class ExternalCalls : public ChunkPass {
private:
    PLTList *pltList;
public:
    ExternalCalls(PLTList *pltList) : pltList(pltList) {}
    virtual void visit(Instruction *instruction);
};

#endif
