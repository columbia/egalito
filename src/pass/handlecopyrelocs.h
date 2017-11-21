#ifndef EGALITO_PASS_HANDLECOPYRELOCS_H
#define EGALITO_PASS_HANDLECOPYRELOCS_H

#include "chunkpass.h"

class Conductor;
class Link;

class HandleCopyRelocs : public ChunkPass {
private:
    Conductor *conductor;
public:
    HandleCopyRelocs(Conductor *conductor) : conductor(conductor) {}
    virtual void visit(Module *module);
private:
    void copyAndDuplicate(Link *link, address_t address, size_t size);
};

#endif
