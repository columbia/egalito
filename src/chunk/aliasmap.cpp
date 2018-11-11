#include <cstring>  // for strstr
#include "aliasmap.h"
#include "concrete.h"
#include "elf/symbol.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dsymbol
#include "log/log.h"

FunctionAliasMap::FunctionAliasMap(Module *module) {
    for(auto func : CIter::functions(module)) {
        auto sym = func->getSymbol();
        if(!sym) continue;

        for(auto aliasSym : sym->getAliases()) {
            if(aliasSym->getType() != Symbol::TYPE_FUNC
                && aliasSym->getType() != Symbol::TYPE_IFUNC) continue;
            auto alias = aliasSym->getName();
            aliasMap[alias] = func;
            LOG(5, "alias [" << alias << "] to [" << func->getName() << "]");

            maybeSpecialAlias(alias, func);
        }

        maybeSpecialAlias(sym->getName(), func);
    }
}

void FunctionAliasMap::maybeSpecialAlias(const char *alias, Function *func) {
    const char *ext[] = {"@@GLIBC", "@GLIBC"};
    for(size_t i = 0; i < sizeof(ext)/sizeof(*ext); i ++) {
        auto specialVersion = std::strstr(alias, ext[i]);
        if(specialVersion) {
            std::string splice(alias, specialVersion - alias);
            aliasMap[splice] = func;
            LOG(5, "SPECIAL alias [" << splice << "] to [" << alias << "]");
            break;
        }
    }
}

Function *FunctionAliasMap::find(const std::string &alias) {
    auto it = aliasMap.find(alias);
    return (it != aliasMap.end() ? (*it).second : nullptr);
}
