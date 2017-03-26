#ifndef EGALITO_PASS_SWITCHCONTEXT_PASS_H
#define EGALITO_PASS_SWITCHCONTEXT_PASS_H

#include "pass/stackextend.h"

/* Make a context that allows a function to be executed
 * without destroying the original context. */

#define EGALITO_CONTEXT_SIZE    (8*16)

#ifdef ARCH_AARCH64
class SwitchContextPass : public StackExtendPass {
private:
    const size_t contextSize;
public:
    SwitchContextPass()
        : StackExtendPass(EGALITO_CONTEXT_SIZE),
          contextSize(EGALITO_CONTEXT_SIZE) {}
private:
    void useStack(Function *function, FrameType *frame);
    void addSaveContextAt(Function *function, FrameType *frame);
    void addRestoreContextAt(Instruction *instruction, FrameType *frame);
};
#endif

#endif
