#ifndef EGALITO_PASS_RESOLVETLS_H
#define EGALITO_PASS_RESOLVETLS_H

#include "chunkpass.h"

class Program;
class Module;
class TLSDataOffsetLink;

class ResolveTLSPass : public ChunkPass {
private:
    Program *program;
    Module *module;
public:
    virtual void visit(Program *program);
    virtual void visit(Module *module);
    virtual void visit(DataRegion *dataRegion);
private:
    void resolveTLSLink(TLSDataOffsetLink *link);
};

#endif
