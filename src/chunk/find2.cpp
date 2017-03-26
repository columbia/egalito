#include "find2.h"
#include "concrete.h"
#include "aliasmap.h"
#include "chunkiter.h"
#include "conductor/conductor.h"
#include "elf/elfspace.h"

Function *ChunkFind2::findFunctionHelper(const char *name, ElfSpace *space) {
    // Search for the function by name.
    auto func = CIter::named(space->getModule()->getFunctionList())
        ->find(name);
    if(func) return func;

    // Also, check if this is an alias for a known function.
    auto alias = space->getAliasMap()->find(name);
    if(alias) return alias;

    return nullptr;
}

Function *ChunkFind2::findFunctionContainingHelper(address_t address,
    ElfSpace *space) {

    auto f = CIter::spatial(space->getModule()->getFunctionList())
        ->findContaining(address);
    return f;
}

Function *ChunkFind2::findFunction(const char *name, ElfSpace *sourceSpace) {
    if(sourceSpace) {
        if(auto f = findFunctionHelper(name, sourceSpace)) return f;
    }

    for(auto library : *conductor->getLibraryList()) {
        auto space = library->getElfSpace();
        if(space && space != sourceSpace) {
            if(auto f = findFunctionHelper(name, space)) return f;
        }
    }

    auto mainSpace = conductor->getMainSpace();
    if(mainSpace != sourceSpace) {
        if(auto f = findFunctionHelper(name, mainSpace)) return f;
    }

    return nullptr;
}

Function *ChunkFind2::findFunctionInSpace(const char *name, ElfSpace *space) {
    return findFunctionHelper(name, space);
}

Function *ChunkFind2::findFunctionContaining(address_t address) {
    auto mainSpace = conductor->getMainSpace();
    if(auto f = findFunctionContainingHelper(address, mainSpace)) return f;
    
    for(auto library : *conductor->getLibraryList()) {
        auto space = library->getElfSpace();
        if(auto f = findFunctionContainingHelper(address, space)) return f;
    }

    return nullptr;
}
