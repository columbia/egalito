#ifndef EGALITO_PASS_NONRETURN_H
#define EGALITO_PASS_NONRETURN_H

#include <vector>
#include "chunkpass.h"

class ControlFlowInstruction;

// This should be run after links to PLTs are resolved
class NonReturnFunction : public ChunkPass {
private:
    const static std::vector<std::string> standardNameList;
    std::vector<Function *> nonReturnList;

public:
    NonReturnFunction() {}
    virtual void visit(Module *module);
    virtual void visit(Function *function);

    const std::vector<Function *>& getList() const { return nonReturnList; }
private:
    bool hasLinkToNonReturn(ControlFlowInstruction *cfi);
    bool inList(Function *function);
};

#endif
