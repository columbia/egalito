#ifndef EGALITO_PASS_ENDBR_ADD_H
#define EGALITO_PASS_ENDBR_ADD_H

#include <set>
#include "chunkpass.h"

class EndbrAddPass : public ChunkPass {
private:
    bool haveCollapsedPLT;
    std::set<Function *> indirectTargets;
public:
    EndbrAddPass(bool haveCollapsedPLT = true) 
        : haveCollapsedPLT(haveCollapsedPLT) {}
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    virtual void visit(DataRegionList *dataRegionList) { recurse(dataRegionList); }
    virtual void visit(DataRegion *dataRegion) { recurse(dataRegion); }
    virtual void visit(DataSection *dataSection) { recurse(dataSection); }
    virtual void visit(DataVariable *dataVariable);
    virtual void visit(PLTList *pltList) { recurse(pltList); }
    virtual void visit(PLTTrampoline *pltTrampoline);
    virtual void visit(InitFunctionList *initFunctionList) { recurse(initFunctionList); }
    virtual void visit(InitFunction *initFunction);
    virtual void visit(Instruction *instruction);
};

#endif
