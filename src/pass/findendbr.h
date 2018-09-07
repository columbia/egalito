#ifndef EGALITO_PASS_FINDENDBR_H
#define EGALITO_PASS_FINDENDBR_H

#include <map>
#include "chunkpass.h"

class FindEndbrPass : public ChunkPass {
private:
    std::map<Function *, int> brCount;
    Function *currentFunction;
public:
    FindEndbrPass() : currentFunction(nullptr) {}
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Instruction *instruction);
};

#endif
