#ifndef EGALITO_PASS_SHADOW_STACK_H
#define EGALITO_PASS_SHADOW_STACK_H

#include "chunkpass.h"

class ShadowStackPass : public ChunkPass {
public:
    enum Mode {
        MODE_CONST,
        MODE_GS,
    };
private:
    Mode mode;
    Function *violationTarget;
public:
    ShadowStackPass(Mode mode = MODE_CONST) : mode(mode),
        violationTarget(nullptr) {}
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    virtual void visit(Function *function);
    virtual void visit(Instruction *instruction);
private:
    void pushToShadowStack(Function *function);
    void pushToShadowStackConst(Function *function);
    void pushToShadowStackGS(Function *function);
    void popFromShadowStack(Instruction *instruction);
    void popFromShadowStackConst(Instruction *instruction);
    void popFromShadowStackGS(Instruction *instruction);
    void instrumentLongjmpGS(Function *function);
    void instrumentSetjmpGS(Function *function);
};


#endif
