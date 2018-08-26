#ifndef EGALITO_TRANSFORM_GENERATOR_H
#define EGALITO_TRANSFORM_GENERATOR_H

#include "sandbox.h"

class PLTTrampoline;

class Generator {
private:
    Sandbox *sandbox;
    bool useDisps;
public:
    Generator(Sandbox *sandbox, bool useDisps = true)
        : sandbox(sandbox), useDisps(useDisps) {}
    void pickAddressesInSandbox(Module *module);
    void copyCodeToSandbox(Module *module);
    void copyPLTEntriesToSandbox(Module *module);
    void instantiate(Function *function);
    void instantiate(PLTTrampoline *trampoline);

    void jumpToSandbox(Sandbox *sandbox, Module *module,
        const char *function = "main");
private:
    void pickFunctionAddressInSandbox(Function *function);
    void pickPLTAddressInSandbox(PLTTrampoline *trampoline);
    void copyFunctionToSandbox(Function *function);
    void copyPLTToSandbox(PLTTrampoline *trampoline);
};

#endif
