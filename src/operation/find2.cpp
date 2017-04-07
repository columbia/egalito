#include "find2.h"
#include "chunk/concrete.h"
#include "chunk/aliasmap.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"

ChunkFind2::ChunkFind2(Conductor *conductor)
    : program(conductor->getProgram()) {

}

Function *ChunkFind2::findFunctionHelper(const char *name, Module *module) {
    // Search for the function by name.
    auto func = CIter::named(module->getFunctionList())
        ->find(name);
    if(func) return func;

    // Also, check if this is an alias for a known function.
    auto alias = module->getElfSpace()->getAliasMap()->find(name);
    if(alias) return alias;

    return nullptr;
}

Function *ChunkFind2::findFunctionContainingHelper(address_t address,
    Module *module) {

    auto f = CIter::spatial(module->getFunctionList())
        ->findContaining(address);
    return f;
}

Function *ChunkFind2::findFunction(const char *name, Module *source) {
    if(source) {
        if(auto f = findFunctionHelper(name, source)) {
            return f;
        }
    }

    for(auto module : CIter::children(program)) {
        if(module == source) continue;
        if(auto f = findFunctionHelper(name, module)) {
            return f;
        }
    }

    return nullptr;
}

Function *ChunkFind2::findFunctionInModule(const char *name, Module *module) {
    return findFunctionHelper(name, module);
}

Function *ChunkFind2::findFunctionContaining(address_t address) {
    for(auto module : CIter::children(program)) {
        if(auto f = findFunctionContainingHelper(address, module)) {
            return f;
        }
    }

    return nullptr;
}
