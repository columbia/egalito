#include <cstring>  // for strstr
#include "aliasmap.h"
#include "concrete.h"
#include "elf/symbol.h"
#include "log/log.h"

FunctionAliasMap::FunctionAliasMap(Module *module) {
    for(auto func : CIter::functions(module)) {
        auto sym = func->getSymbol();
        for(auto aliasSym : sym->getAliases()) {
            if(aliasSym->getType() != Symbol::TYPE_FUNC) continue;
            auto alias = aliasSym->getName();
            //LOG(1, alias << " is an alias for " << func->getName());
            aliasMap[alias] = func;

            auto specialVersion = std::strstr(alias, "@@GLIBC");
            if(specialVersion) {
                std::string splice(alias, specialVersion - alias);
                aliasMap[splice] = func;
                LOG(1, "alias [" << splice << "] to [" << alias << "]");
            }
        }

        auto name = sym->getName();
        auto specialVersion = std::strstr(name, "@@GLIBC");
        if(specialVersion) {
            std::string splice(name, specialVersion - name);
            aliasMap[splice] = func;
            LOG(1, "alias [" << splice << "] to [" << name << "]");
        }
    }
}

Function *FunctionAliasMap::find(const std::string &alias) {
    auto it = aliasMap.find(alias);
    return (it != aliasMap.end() ? (*it).second : nullptr);
}
