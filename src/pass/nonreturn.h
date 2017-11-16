#ifndef EGALITO_PASS_NONRETURN_H
#define EGALITO_PASS_NONRETURN_H

#include <vector>
#include "chunkpass.h"

class ControlFlowInstruction;
class UDState;

class NonReturnFunction : public ChunkPass {
private:
    const static std::vector<std::string> knownList;
    std::vector<Function *> nonReturnList;

public:
    NonReturnFunction() {}
    virtual void visit(Module *module);
    virtual void visit(Function *function);

    const std::vector<Function *>& getList() const { return nonReturnList; }
private:
    bool neverReturns(Function *function);
    bool hasLinkToNeverReturn(ControlFlowInstruction *cfi);
    bool inList(Function *function);

    bool hasLinkToGNUError(ControlFlowInstruction *cfi);
    std::tuple<bool, int> getArg0Value(UDState *state);
};

#endif
