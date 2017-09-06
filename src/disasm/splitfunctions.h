#ifndef EGALITO_DISASM_SPLIT_FUNCTIONS_H
#define EGALITO_DISASM_SPLIT_FUNCTIONS_H

#include "chunk/module.h"

class SplitFunctions {
public:
    static void splitByDirectCall(Module *module);
private:
    static void useFunctionList(Module *module, FunctionList *newList);
    static void deleteFunctionList(Module *module);
    static void setFunctionList(Module *module, FunctionList *newList);
};

#endif
