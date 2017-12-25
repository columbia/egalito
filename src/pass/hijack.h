#ifndef EGALITO_PASS_HIJACKPASS_H
#define EGALITO_PASS_HIJACKPASS_H

#include "pass/chunkpass.h"

class HijackPass : public ChunkPass {
private:
    Chunk *original;
    Chunk *wrapper;
public:
    HijackPass(Conductor *conductor, const char *name);
    void visit(Module *module);
private:
    void visit(Instruction *instruction);
    void visit(PLTTrampoline *trampoline);
};

#endif
