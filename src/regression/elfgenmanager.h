#ifndef EGALITO_REGRESSION_ELFGENMANAGER_H
#define EGALITO_REGRESSION_ELFGENMANAGER_H

#include "transform/sandbox.h"
#include "elf/elfspace.h"

class ElfGenManager {
private:
    ElfSpace *elfSpace;
    Sandbox *sandbox;
public:
    ElfGenManager(ElfSpace *elfSpace)
        : elfSpace(elfSpace), sandbox(nullptr) {}
public:
    void copyCodeToSandbox();

    void setSandbox(Sandbox *box) { sandbox = box; }
    Sandbox *getSandbox() const { return sandbox; }
};

#endif
