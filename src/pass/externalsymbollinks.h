#ifndef EGALITO_PASS_EXTERNALSYMBOLLINKS_H
#define EGALITO_PASS_EXTERNALSYMBOLLINKS_H

#include "chunkpass.h"

/** Find all links whose target is null, replace with ExternalSymbolLink.
    Used in mirrorgen when parsing only one Module.
*/
class ExternalSymbolLinksPass : public ChunkPass {
public:
    virtual void visit(Module *module);
};

#endif
