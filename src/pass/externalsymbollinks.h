#ifndef EGALITO_PASS_EXTERNALSYMBOLLINKS_H
#define EGALITO_PASS_EXTERNALSYMBOLLINKS_H

#include "chunkpass.h"

class ExternalSymbolLinksPass : public ChunkPass {
public:
    virtual void visit(Module *module);
};

#endif
