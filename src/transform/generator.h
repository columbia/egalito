#ifndef EGALITO_TRANSFORM_GENERATOR_H
#define EGALITO_TRANSFORM_GENERATOR_H

#include "sandbox.h"

class Generator {
public:
    Sandbox *makeSandbox();
    void copyCodeToSandbox(ElfMap *elf, Module *module,
        Sandbox *sandbox);
    void jumpToSandbox(Sandbox *sandbox, Module *module,
        const char *function = "main");
};

#endif
