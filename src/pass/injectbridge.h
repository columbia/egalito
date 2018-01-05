#ifndef EGALITO_PASS_INJECTBRIDGE_H
#define EGALITO_PASS_INJECTBRIDGE_H

#include "chunkpass.h"

class RelocList;
class Reloc;

class InjectBridgePass : public ChunkPass {
private:
    RelocList *relocList;
public:
    InjectBridgePass(RelocList *relocList) : relocList(relocList) {}
    void visit(Module *module);
private:
    void makeLinkToLoaderVariable(Module *module, Reloc *reloc);
};

#endif
