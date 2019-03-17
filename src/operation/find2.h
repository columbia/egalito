#ifndef EGALITO_OPERATION_FIND2_H
#define EGALITO_OPERATION_FIND2_H

#include "types.h"

class Conductor;
class Program;
class Module;
class Function;
class PLTTrampoline;

class ChunkFind2 {
private:
    Program *program;
public:
    ChunkFind2(Conductor *conductor);
    ChunkFind2(Program *program) : program(program) {}
    ChunkFind2() : program(nullptr) {}

    Function *findFunction(const char *name, Module *source = nullptr);
    Function *findFunctionInModule(const char *name, Module *module);

    Function *findFunctionContaining(address_t address);
    Function *findFunctionContainingInModule(address_t address, Module *module);
    
    
    PLTTrampoline *findPLTTrampoline(const char* name, Module *source = nullptr);

 
private:
    Function *findFunctionHelper(const char *name, Module *module);
    PLTTrampoline *findPLTTrampolineHelper(const char* name, Module *module);
};

#endif
