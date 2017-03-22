#ifndef EGALITO_PASS_LOG_CALLS_H
#define EGALITO_PASS_LOG_CALLS_H

#include "chunkpass.h"

class Conductor;

class LogCallsPass : public ChunkPass {
private:
    Function *loggingBegin, *loggingEnd;
public:
    LogCallsPass(Conductor *conductor);
    virtual void visit(Function *function);
    virtual void visit(Instruction *instruction);
private:
    void addEntryInstructionsAt(Block *block);
    void addExitInstructionsAt(Instruction *instruction);
};

#endif
