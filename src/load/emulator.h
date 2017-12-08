#ifndef EGALITO_LOAD_EMULATOR_H
#define EGALITO_LOAD_EMULATOR_H

#include <string>
#include <map>
#include "types.h"

class Conductor;
class Module;
class Function;
class Link;
class DataVariable;

/** Emulate functionality provided by ld.so. */
class LoaderEmulator {
private:
    Module *egalito;
    static LoaderEmulator instance;
public:
    static LoaderEmulator &getInstance() { return instance; }
private:
    std::map<std::string, Function *> functionMap;
    std::map<std::string, address_t> dataMap;
public:
    void setup(Conductor *conductor);

    void setArgumentLinks(char **argv, char **envp);
    void initRT(Conductor *conductor);

    Function *findFunction(const std::string &symbol);
    Link *makeDataLink(const std::string &symbol);
private:
    LoaderEmulator() : egalito(nullptr) {}

    DataVariable *findEgalitoDataVariable(const char *name);

    void addFunction(const std::string &symbol, Function *function);
    void addData(const std::string &symbol, address_t address);
};

#endif
