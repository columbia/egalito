#ifndef EGALITO_OPERATION_FIND2_H
#define EGALITO_OPERATION_FIND2_H

#include "types.h"

class Conductor;
class Program;
class Module;
class Function;

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
private:
    Function *findFunctionHelper(const char *name, Module *module);
    Function *findFunctionContainingHelper(address_t address, Module *module);
};

#endif
