#ifndef EGALITO_PASS_RETPOLINE_H
#define EGALITO_PASS_RETPOLINE_H

#include <map>
#include <vector>
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
    void log_instruction(Instruction *instr, const char *message);
    Function *makeOutlinedTrampoline(Module *module, Instruction *instr);
    std::vector<Instruction *> makeMovInstruction(Instruction *instr);
    std::vector<Instruction *> makeMovInstructionDataLinked(Instruction *instr);
};

#endif
