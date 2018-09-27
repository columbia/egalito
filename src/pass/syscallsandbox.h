#ifndef EGALITO_PASS_SYSCALL_SANDBOX_H
#define EGALITO_PASS_SYSCALL_SANDBOX_H

#include "chunkpass.h"

class SyscallSandbox : public ChunkPass {
private:
    Program *program;
public:
    SyscallSandbox(Program *program) : program(program) {}
    virtual void visit(Function *function);
private:   
    void addEnforcement(Function *function, Instruction *syscallInstr, Function*enforce);
};

#endif
