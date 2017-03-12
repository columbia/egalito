#include <cassert>
#include "emulator.h"

namespace Emulation {
    #include "dep/rtld.h"

    struct rtld_global _rtld_global;
    struct rtld_global_ro _rtld_global_ro;
    char **_dl_argv;
    int _dl_starting_up = 1;
    void *not_yet_implemented = 0;
}

void LoaderEmulator::useArgv(char **argv) {
    Emulation::_dl_argv = argv;
    addSymbol("_dl_argv", Emulation::_dl_argv);
    addSymbol("_dl_starting_up", &Emulation::_dl_starting_up);

    addSymbol("__libc_enable_secure", Emulation::not_yet_implemented);
    addSymbol("_dl_find_dso_for_object", Emulation::not_yet_implemented);
    addSymbol("__tls_get_addr", Emulation::not_yet_implemented);

    addSymbol("_rtld_global", &Emulation::_rtld_global);
    addSymbol("_rtld_global_ro", &Emulation::_rtld_global_ro);
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
