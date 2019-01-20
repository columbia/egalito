#ifndef EGALITO_CONDUCTOR_PASSES_H
#define EGALITO_CONDUCTOR_PASSES_H

#include "elf/elfspace.h"

class ConductorPasses {
private:
    Conductor *conductor;
public:
    ConductorPasses(Conductor *conductor) : conductor(conductor) {}
    void newElfPasses(ElfSpace *space);
    void newArchivePasses(Program *program);
    void newExecutablePasses(Program *program);
    void newMirrorPasses(Program *program);
    void reloadedArchivePasses(Module *module);
};

#endif
