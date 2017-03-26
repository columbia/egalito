#ifndef EGALITO_PASS_INSTRUMENTCALLS_PASS_H
#define EGALITO_PASS_INSTRUMENTCALLS_PASS_H

#include "pass/stackextend.h"

/* The assumption is that the advice is transformed by SwitchContextPass. */

#define FUNCTIONCALL_CONTEXT_SIZE   (1*16)

#ifdef ARCH_AARCH64
class InstrumentCallsPass : public StackExtendPass {
public:
    typedef bool (*predicate_t) (Function *function);

private:
    Function *entry;
    Function *exit;
    predicate_t predicate;

public:
    InstrumentCallsPass(Function *entry, Function *exit)
        : StackExtendPass(FUNCTIONCALL_CONTEXT_SIZE),
          entry(entry), exit(exit), predicate(nullptr) {}
    void setPredicate(predicate_t predicate) { this->predicate = predicate; }

private:
    void useStack(Function *function, FrameType *frame);
    void addEntryAdvice(Function *function, FrameType *frame);
    void addExitAdvice(Function *function, FrameType *frame);
    void addAdvice(Instruction *point, Function *advice, bool before);
    bool shouldApply(Function *function) {
        return function != entry && function != exit
            && (predicate ? predicate(function) : true); }
};
#endif

#endif

