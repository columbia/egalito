#ifndef EGALITO_PASS_HANDLEDATARELOCS_H
#define EGALITO_PASS_HANDLEDATARELOCS_H

#include "chunkpass.h"

class Reloc;
class Link;

class HandleDataRelocsPass : public ChunkPass {
private:
    RelocList *relocList;
    bool internal;
    bool weak;
    Conductor *conductor;
protected:
    HandleDataRelocsPass(RelocList *relocList, bool internal, bool weak,
        Conductor *conductor)
        : relocList(relocList), internal(internal), weak(weak),
        conductor(conductor) {}
public:
    virtual void visit(Module *module);
private:
    void resolveSpecificRelocSection(RelocSection *relocSection,
        Module *module);
    void resolveGeneralRelocSection(RelocSection *relocSection,
        Module *module);
    Link *resolveVariableLink(Reloc *reloc, Module *module);
};

class HandleDataRelocsInternalStrong : public HandleDataRelocsPass {
public:
    HandleDataRelocsInternalStrong(RelocList *relocList, Conductor *conductor = nullptr)
        : HandleDataRelocsPass(relocList, true, false, conductor) {}
};

class HandleDataRelocsInternalWeak : public HandleDataRelocsPass {
public:
    HandleDataRelocsInternalWeak(RelocList *relocList)
        : HandleDataRelocsPass(relocList, true, true, nullptr) {}
};

class HandleDataRelocsExternalStrong : public HandleDataRelocsPass {
public:
    HandleDataRelocsExternalStrong(RelocList *relocList, Conductor *conductor)
        : HandleDataRelocsPass(relocList, false, false, conductor) {}
};

class HandleDataRelocsExternalWeak : public HandleDataRelocsPass {
public:
    HandleDataRelocsExternalWeak(RelocList *relocList, Conductor *conductor)
        : HandleDataRelocsPass(relocList, false, true, conductor) {}
};

#endif
