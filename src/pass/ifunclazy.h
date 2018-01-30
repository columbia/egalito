#ifndef EGALITO_PASS_IFUNCLAZY_H
#define EGALITO_PASS_IFUNCLAZY_H

#include "chunkpass.h"

// relocation is not aware of the lazy selection

class IFuncList;

// this pass does not work in the following case (all conditions met):
// - when the target has a plt to IFUNC
// - when the target has a function pointer to IFUNC
// In this case, gcc creates R_X86_64_GLOB_DAT, instead of R_X86_64_JUMP_SLOT.
// In other words, if there is a .plt.got section. This section holds
// special PLT trampolines that works, when ld has combined
// a normal GOT entry and one needed by PLT.
//
// A workaround for this is to have a run-time constructor that
// pre-resolves all IFUNCs (including the internal ones in glibc)
// A proper fix would be to handle this PLT specially.
// The current workaround is abuse CollapsePLTPass.
class IFuncLazyPass : public ChunkPass {
private:
    IFuncList *ifuncList;
    Module *module;
public:
    IFuncLazyPass(IFuncList *ifuncList) : ifuncList(ifuncList) {}
private:
    virtual void visit(Module *module);
    virtual void visit(PLTTrampoline *trampoline);
};

#endif
