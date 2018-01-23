#ifndef EGALITO_PASS_RETPOLINE_H
#define EGALITO_PASS_RETPOLINE_H

#include <map>
#include <string>
#include "chunkpass.h"

class RetpolinePass : public ChunkPass {
private:
    std::map<std::string, Function *> retpolineList;
    Module *module;
public:
    RetpolinePass() : module(nullptr) {}
    virtual void visit(Module *module);
protected:
    virtual void visit(Function *function);
private:
    Function *makeOutlinedTrampoline(Module *module, Instruction *instr);
    Instruction *makeMovInstruction(Instruction *instr);
};

#endif
