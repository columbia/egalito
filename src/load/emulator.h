#ifndef EGALITO_LOAD_EMULATOR_H
#define EGALITO_LOAD_EMULATOR_H

#include <string>
#include <map>
#include "types.h"

/** Emulate functionality provided by ld.so. */
class LoaderEmulator {
private:
    static LoaderEmulator instance;
public:
    static LoaderEmulator &getInstance() { return instance; }
private:
    std::map<std::string, address_t> symbolMap;
public:
    void useArgv(char **argv);

    address_t findSymbol(const std::string &symbol);
private:
    LoaderEmulator();

    void addSymbol(const std::string &symbol, const void *address);
};

#endif
