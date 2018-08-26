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

    void assignAddresses(Program *program);
    void generateCode(Program *program);

    void assignAddresses(Module *module);
    void generateCode(Module *module);

    // For JIT-Shuffling. Assign an address and generate code.
    void assignAndGenerate(Function *function);
    void assignAndGenerate(PLTTrampoline *trampoline);

    // For testing purposes only. Jumps directly to main, skipping init.
    void jumpToSandbox(Module *module, const char *function = "main");
private:
    void pickFunctionAddressInSandbox(Function *function);
    void pickPLTAddressInSandbox(PLTTrampoline *trampoline);
    void copyFunctionToSandbox(Function *function);
    void copyPLTToSandbox(PLTTrampoline *trampoline);
};

#endif
