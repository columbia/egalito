#ifndef EGALITO_PASS_FIXIFUNCSLOT_H
#define EGALITO_PASS_FIXIFUNCSLOT_H

#include "chunkpass.h"

// relocation is not aware of the lazy selection

class FixIFuncSlotPass : public ChunkPass {
private:
    Module *module;
private:
    virtual void visit(Module *module);
    virtual void visit(PLTTrampoline *trampoline);
};

#endif
