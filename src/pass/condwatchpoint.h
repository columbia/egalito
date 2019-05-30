#ifndef EGALITO_PASS_COND_WATCHPOINT_H
#define EGALITO_PASS_COND_WATCHPOINT_H

#include <utility>
#include "chunkpass.h"
#include "chunk/dataregion.h"
#include "chunk/function.h"

class CondWatchpointPass : public ChunkPass {
private:
    Function *condTarget;
public:
    virtual void visit(Module *module);
    virtual void visit(Function *function);
private:
    std::pair<DataSection *, DataSection*> createDataSection(Module *module);
    Link *addVariable(DataSection *section, Function *function);
    void appendFunctionName(DataSection *nameSection, const std::string &name);
};

#endif
