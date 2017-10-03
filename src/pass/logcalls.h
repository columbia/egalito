#ifndef EGALITO_PASS_LOG_CALLS_H
#define EGALITO_PASS_LOG_CALLS_H

#include "chunkpass.h"
#include "pass/instrumentinstr.h"

class Conductor;

// keeping the same name for now; we should really have one implementation
class LogCallsPass : public ChunkPass {
private:
    Function *loggingFunc;
    InstrumentInstructionPass instrument;
public:
    LogCallsPass(Conductor *conductor);
    virtual void visit(Function *function);
};

#endif
