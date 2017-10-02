#ifndef EGALITO_PASS_INSTRUMENTCALLS_PASS_H
#define EGALITO_PASS_INSTRUMENTCALLS_PASS_H

#include "pass/stackextend.h"

/* The assumption is that the advice is transformed by SwitchContextPass. */

// This should be zero so that it will still survive even when the number of
// entry and exit don't match
#define FUNCTIONCALL_CONTEXT_SIZE   0//(1*16)

class InstrumentCallsPass : public StackExtendPass {
public:
    typedef bool (*predicate_t) (Function *function);

private:
    Function *entry;
    Function *exit;
    predicate_t predicate;
public:
    InstrumentCallsPass()
        : StackExtendPass(FUNCTIONCALL_CONTEXT_SIZE),
          entry(nullptr), exit(nullptr), predicate(nullptr) {}
    void setPredicate(predicate_t predicate) { this->predicate = predicate; }
    void setEntryAdvice(Function *entry) { this->entry = entry; }
    void setExitAdvice(Function *exit) { this->exit = exit; }

private:
    virtual void useStack(Function *function, FrameType *frame);
    void addEntryAdvice(Function *function, FrameType *frame);
    void addExitAdvice(Function *function, FrameType *frame);
    void addAdvice(Instruction *point, Function *advice, bool before);
    virtual bool shouldApply(Function *function) {
        return function != entry && function != exit
            && (predicate ? predicate(function) : true); }
};

#endif
