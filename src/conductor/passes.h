#ifndef EGALITO_CONDUCTOR_PASSES_H
#define EGALITO_CONDUCTOR_PASSES_H

#include "elf/elfspace.h"

class ConductorPasses {
public:
    void newElfPasses(ElfSpace *space);
    void newArchivePasses(Program *program);
};

#endif
