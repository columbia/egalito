#ifndef EGALITO_PASS_INSTRUMENTINSTR_PASS_H
#define EGALITO_PASS_INSTRUMENTINSTR_PASS_H

#include "pass/stackextend.h"

class InstrumentInstructionPass : public ChunkPass {
public:
    typedef bool (*predicate_t) (Function *function);
private:
    Function *func;
    predicate_t predicate;
public:
    InstrumentInstructionPass() : func(nullptr), predicate(nullptr) {}
    void setPredicate(predicate_t predicate) { this->predicate = predicate; }
    void setAdvice(Function *func) { this->func = func; }

    virtual void visit(Function *function);
    virtual void visit(Block *block);
    virtual void visit(Instruction *instruction);

private:
    void addAdvice(Instruction *point, Function *advice, bool before);
    virtual bool shouldApply(Function *function) {
        return function != func
            && (predicate ? predicate(function) : true); }
};

#endif
