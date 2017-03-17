#include "aliasmap.h"
#include "concrete.h"
#include "log/log.h"

FunctionAliasMap::FunctionAliasMap(Module *module) {
    for(auto func : module->getChildren()->getIterable()->iterable()) {
        auto sym = func->getSymbol();
        for(auto aliasSym : sym->getAliases()) {
            auto alias = aliasSym->getName();
            //LOG(1, alias << " is an alias for " << func->getName());
            aliasMap[alias] = func;

#if 1
            auto specialVersion = strstr(alias, "@@GLIBC");
            if(specialVersion) {
                std::string splice(alias, specialVersion - alias);
                aliasMap[splice] = func;
                LOG(1, "alias [" << splice << "] to [" << alias << "]");
            }
#endif
        }

#if 1
        auto name = sym->getName();
        auto specialVersion = strstr(name, "@@GLIBC");
        if(specialVersion) {
            std::string splice(name, specialVersion - name);
            aliasMap[splice] = func;
            LOG(1, "alias [" << splice << "] to [" << name << "]");
        }
#endif
    }
}

Function *FunctionAliasMap::find(const std::string &alias) {
    auto it = aliasMap.find(alias);
    return (it != aliasMap.end() ? (*it).second : nullptr);
}
