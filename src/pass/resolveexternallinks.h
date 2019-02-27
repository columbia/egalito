#ifndef EGALITO_PASS_RESOLVEEXTERNALLINKS_H
#define EGALITO_PASS_RESOLVEEXTERNALLINKS_H

#include "chunkpass.h"

class ResolveExternalLinksPass : public ChunkPass {
private:
    Conductor *conductor;
public:
    ResolveExternalLinksPass(Conductor *conductor) : conductor(conductor) {}
    virtual void visit(Module *module);
};

#endif
