#ifndef EGALITO_JIT_GS_FIXUP_H
#define EGALITO_JIT_GS_FIXUP_H

#include "chunkpass.h"

class Conductor;
class GSTable;

class JitGSFixup : public ChunkPass {
private:
    Conductor *conductor;
    GSTable *gsTable;
    Chunk *callback;
public:
    JitGSFixup(Conductor *conductor, GSTable *gsTable);

    virtual void visit(Program *program);
private:
    void resetGSTable();
    void addResetCall();
};

#endif
