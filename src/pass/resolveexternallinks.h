#ifndef EGALITO_PASS_RESOLVEEXTERNALLINKS_H
#define EGALITO_PASS_RESOLVEEXTERNALLINKS_H

#include "chunkpass.h"

/** Re-resolve external links between modules, after all modules are loaded
    and more targets may be known. Used in parse2/parse3.
*/
class ResolveExternalLinksPass : public ChunkPass {
private:
    Conductor *conductor;
public:
    ResolveExternalLinksPass(Conductor *conductor) : conductor(conductor) {}
    virtual void visit(Module *module);
};

#endif
