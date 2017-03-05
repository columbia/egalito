#include "emulator.h"

namespace Emulation {
    char **__environ;
    const char *__progname_full;
}

void LoaderEmulator::useArgv(char **argv) {
#if 0
    while(argv) argv ++;
    argv ++;
    Emulation::__environ = argv;

    addSymbol("__environ", Emulation::__environ);

    Emulation::__progname_full = argv[0];
    addSymbol("__progname_full", Emulation::__progname_full);
#endif
}

LoaderEmulator LoaderEmulator::instance;

LoaderEmulator::LoaderEmulator() {
}

address_t LoaderEmulator::findSymbol(const std::string &symbol) {
    auto it = symbolMap.find(symbol);
    return (it != symbolMap.end() ? (*it).second : 0);
}

void LoaderEmulator::addSymbol(const std::string &symbol, const void *address) {
    symbolMap[symbol] = reinterpret_cast<address_t>(address);
}
