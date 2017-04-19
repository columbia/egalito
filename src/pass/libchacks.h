#ifndef EGALITO_PASS_LIBC_HACKS_H
#define EGALITO_PASS_LIBC_HACKS_H

#include "chunkpass.h"

class LibcHacksPass : public ChunkPass {
private:
    Program *program;
public:
    LibcHacksPass(Program *program) : program(program) {}
    virtual void visit(Module *module);
private:
    void fixFunction(Function *func);
};

#endif
