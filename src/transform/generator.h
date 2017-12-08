#ifndef EGALITO_TRANSFORM_GENERATOR_H
#define EGALITO_TRANSFORM_GENERATOR_H

#include "sandbox.h"

class PLTTrampoline;

class Generator {
private:
    bool useDisps;
public:
    Generator(bool useDisps = true) : useDisps(useDisps) {}
    void pickAddressesInSandbox(Module *module, Sandbox *sandbox);
    void copyCodeToSandbox(Module *module, Sandbox *sandbox);
    void copyFunctionToSandbox(Function *function, Sandbox *sandbox);
    void copyPLTEntriesToSandbox(Module *module, Sandbox *sandbox);
    void copyPLTToSandbox(PLTTrampoline *trampoline, Sandbox *sandbox);

    void jumpToSandbox(Sandbox *sandbox, Module *module,
        const char *function = "main");
};

#endif
