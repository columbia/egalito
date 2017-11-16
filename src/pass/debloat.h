#ifndef EGALITO_PASS_DEBLOAT_H
#define EGALITO_PASS_DEBLOAT_H

#include "chunkpass.h"
#include "analysis/call.h"

class DebloatPass : public ChunkPass {
private:
    Program *program;
    CallGraph graph;
    std::set<Function *> usedList;
public:
    DebloatPass(Program *program);
    virtual void visit(Module *module);
private:
    void useFromDynamicInitFini();
    void useFromPointerArray(address_t start, size_t size, Module *module);
    void useFromEntry();
    void useFromIndirectCallee();
    void useFromCodeLinks();
    void markTreeAsUsed(Function *root);
};

#endif
