#include "aliasmap.h"
#include "concrete.h"
#include "log/log.h"

FunctionAliasMap::FunctionAliasMap(Module *module) {
    for(auto func : module->getChildren()->getIterable()->iterable()) {
        for(auto alias : func->getSymbol()->getAliases()) {
            LOG(1, alias << " is an alias for " << func->getName());
            aliasMap[alias] = func;
        }
    }
}

Function *FunctionAliasMap::find(const std::string &alias) {
    auto it = aliasMap.find(alias);
    return (it != aliasMap.end() ? (*it).second : nullptr);
}
