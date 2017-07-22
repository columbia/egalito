#ifndef EGALITO_PASS_LOG_CALLS_H
#define EGALITO_PASS_LOG_CALLS_H

#include "chunkpass.h"
#ifdef ARCH_AARCH64
#include "pass/instrumentcalls.h"
#endif

class Conductor;

// keeping the same name for now; we should really have one implementation
class LogCallsPass : public ChunkPass {
private:
    Function *loggingBegin, *loggingEnd;
#ifdef ARCH_AARCH64
    InstrumentCallsPass instrument;
#endif
public:
    LogCallsPass(Conductor *conductor);
    virtual void visit(Function *function);
#ifdef ARCH_X86_64
    virtual void visit(Instruction *instruction);
private:
    void addEntryInstructionsAt(Block *block);
    void addExitInstructionsAt(Instruction *instruction);
#endif
};

#endif
