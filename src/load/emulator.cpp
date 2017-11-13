#include <cassert>
#include <cstring>  // for memcpy in generated code
#include "emulator.h"

namespace Emulation {
    #include "dep/rtld/rtld.h"

    struct my_rtld_global _rtld_global;
    struct my_rtld_global_ro _rtld_global_ro;
    char **_dl_argv;
    char **__environ;           // for libc, musl
    int _dl_starting_up = 0;//1;
    int __libc_enable_secure = 1;
    void *not_yet_implemented = 0;

    static void init_rtld_global(struct my_rtld_global *s) {
        using std::memcpy;
        #include "dep/rtld/rtld_data1.c"
    }
    static void init_rtld_global_ro(struct my_rtld_global_ro *s) {
        using std::memcpy;
        #include "dep/rtld/rtld_data2.c"
    }

    static int function_not_implemented(void) { return 0; }
}

void LoaderEmulator::useArgv(char **argv) {
    Emulation::_dl_argv = argv;
    addSymbol("_dl_argv", Emulation::_dl_argv);

    char **environ = argv;
    while(*environ) environ ++;
    environ ++;
    Emulation::__environ = environ;
}

LoaderEmulator LoaderEmulator::instance;

LoaderEmulator::LoaderEmulator() {
    addSymbol("__environ", &Emulation::__environ);
    addSymbol("environ", &Emulation::__environ);

    addSymbol("_dl_starting_up", Emulation::_dl_starting_up);
    addSymbol("__libc_enable_secure", &Emulation::__libc_enable_secure);
    //addSymbol("__libc_enable_secure", Emulation::not_yet_implemented);

    addSymbol("_dl_find_dso_for_object", (void *)Emulation::function_not_implemented);
    addSymbol("__tunable_get_val", (void *)Emulation::function_not_implemented);
    addSymbol("__tunable_set_val", (void *)Emulation::function_not_implemented);
    addSymbol("__tls_get_addr", Emulation::not_yet_implemented);

    Emulation::init_rtld_global(&Emulation::_rtld_global);
    Emulation::init_rtld_global_ro(&Emulation::_rtld_global_ro);

    Emulation::_rtld_global._dl_rtld_lock_recursive
        = (void *)&Emulation::function_not_implemented;
    Emulation::_rtld_global._dl_rtld_unlock_recursive
        = (void *)&Emulation::function_not_implemented;

    addSymbol("_rtld_global", &Emulation::_rtld_global);
    addSymbol("_rtld_global_ro", &Emulation::_rtld_global_ro);

    Emulation::_rtld_global_ro._dl_lookup_symbol_x
        = (void *)&Emulation::function_not_implemented;
}

address_t LoaderEmulator::findSymbol(const std::string &symbol) {
    auto it = symbolMap.find(symbol);
    return (it != symbolMap.end() ? (*it).second : 0);
}

void LoaderEmulator::addSymbol(const std::string &symbol, const void *address) {
    symbolMap[symbol] = reinterpret_cast<address_t>(address);
}

void LoaderEmulator::addSymbol(const std::string &symbol, address_t address) {
    symbolMap[symbol] = address;
}
