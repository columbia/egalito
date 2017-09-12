#ifndef EGALITO_CHUNK_ALIAS_MAP_H
#define EGALITO_CHUNK_ALIAS_MAP_H

#include <string>
#include <map>

class Function;
class Module;

/** Allows functions to be looked up by their alias names.

    Note: a function's main name is not registered in this data structure.
*/
class FunctionAliasMap {
private:
    std::map<std::string, Function *> aliasMap;
public:
    FunctionAliasMap(Module *module);

    Function *find(const std::string &alias);
private:
    void maybeSpecialAlias(const char *alias, Function *func);
};

#endif
