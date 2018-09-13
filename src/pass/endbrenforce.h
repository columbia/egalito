#ifndef EGALITO_PASS_ENDBR_ENFORCE_H
#define EGALITO_PASS_ENDBR_ENFORCE_H

#include "chunkpass.h"

class EndbrEnforcePass : public ChunkPass {
private:
    Function *violationTarget;
public:
    EndbrEnforcePass() : violationTarget(nullptr) {}
    virtual void visit(Module *module);
    virtual void visit(Instruction *instruction);
private:
    void makeEnforcementCode(Instruction *point); 
};


#endif
