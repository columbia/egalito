#ifndef EGALITO_JIT_GS_FIXUP_H
#define EGALITO_JIT_GS_FIXUP_H

#include "chunkpass.h"

class Conductor;
class GSTable;
class Module;

class JitGSFixup : public ChunkPass {
private:
    Conductor *conductor;
    GSTable *gsTable;
    Chunk *callback;
public:
    JitGSFixup(Conductor *conductor, GSTable *gsTable);

    virtual void visit(Program *program);
private:
    void addResetCalls();
    void addAfterFirstSyscall(const char *name, Module *module, Chunk *target);
    void addAfterEverySyscall(const char *name, Module *module, Chunk *target);
    void addAfterSyscall(const char *name, Module *module, Chunk *target,
        bool firstOnly);
    void addAfter(Instruction *instruction, Block *block, Chunk *target);
};

#endif
