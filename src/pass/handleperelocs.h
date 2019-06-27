#ifndef EGALITO_PASS_HANDLEPERELOCS_H
#define EGALITO_PASS_HANDLEPERELOCS_H

#include "chunkpass.h"

class Reloc;
class Link;

class HandlePERelocsPass : public ChunkPass {
public:
    virtual void visit(Module *module);
private:
    Link *makeLink(Module *module, Reloc *reloc);
};

#endif
