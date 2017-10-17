#ifndef EGALITO_PASS_LOG_INSTR_H
#define EGALITO_PASS_LOG_INSTR_H

#include "chunkpass.h"
#include "pass/instrumentinstr.h"

class Conductor;

// keeping the same name for now; we should really have one implementation
class LogInstructionPass : public ChunkPass {
private:
    Function *loggingFunc;
    InstrumentInstructionPass instrument;
public:
    LogInstructionPass(Conductor *conductor);
    virtual void visit(Function *function);
};

#endif
