#ifndef EGALITO_PASS_NONRETURN_H
#define EGALITO_PASS_NONRETURN_H

#include <set>
#include "chunkpass.h"

class ControlFlowInstruction;
class UDState;

class NonReturnFunction : public ChunkPass {
private:
    const static std::vector<std::string> knownList;
    std::set<Function *> nonReturnList;

public:
    NonReturnFunction() {}
    virtual void visit(FunctionList *functionList);
    virtual void visit(Function *function);
private:
    bool neverReturns(Function *function);
    bool hasLinkToNeverReturn(ControlFlowInstruction *cfi);
    bool inList(Function *function);

    bool hasLinkToGNUError(ControlFlowInstruction *cfi);
    std::tuple<bool, int> getArg0Value(UDState *state);
};

#endif
