#ifndef EGALITO_CHUNK_ALIAS_MAP_H
#define EGALITO_CHUNK_ALIAS_MAP_H

#include <string>
#include <map>

class Function;
class Module;

class FunctionAliasMap {
private:
    std::map<std::string, Function *> aliasMap;
public:
    FunctionAliasMap(Module *module);

    Function *find(const std::string &alias);
};

#endif
