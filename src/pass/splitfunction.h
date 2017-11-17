#ifndef EGALITO_PASS_SPLITFUNCTION_H
#define EGALITO_PASS_SPLITFUNCTION_H

#include "chunkpass.h"

class FunctionList;
class Function;

class SplitFunction : public ChunkPass {
private:
    // must be an ordered container
    std::vector<std::pair<Function *, Block *>> splitPoints;
public:
    SplitFunction() {}
    virtual void visit(FunctionList *functionList);
    virtual void visit(Function *function);
};

#endif
