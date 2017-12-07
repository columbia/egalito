#include <cstring>  // for memcpy in generated code
#include "emulator.h"
#include "chunk/link.h"
#include "conductor/conductor.h"
#include "operation/find2.h"

namespace Emulation {
    #include "../dep/rtld/rtld.h"

    struct my_rtld_global _rtld_global;
    struct my_rtld_global_ro _rtld_global_ro;
    char **_dl_argv;
    char **__environ;           // for libc, musl
    int _dl_starting_up = 0;//1;
    int __libc_enable_secure = 1;
    void *not_yet_implemented = 0;

    static void init_rtld_global(struct my_rtld_global *s) {
        using std::memcpy;
        #include "../dep/rtld/rtld_data1.c"
    }
    static void init_rtld_global_ro(struct my_rtld_global_ro *s) {
        using std::memcpy;
        #include "../dep/rtld/rtld_data2.c"
    }

    int function_not_implemented(void) { return 0; }
}

static void createDataVariable2(address_t address, void *target,
    Module *egalito) {

    auto targetAddress = reinterpret_cast<address_t>(target);
    address += egalito->getElfSpace()->getElfMap()->getBaseAddress();
    auto region = egalito->getDataRegionList()->findRegionContaining(address);
    auto link = new StackLink(targetAddress);
    auto var = new DataVariable(region, address, link);
    region->addVariable(var);
}

void LoaderEmulator::setArgumentLinks(char **argv, char **envp) {
    if(!egalito || !egalito->getElfSpace()) return;
    auto symbolList = egalito->getElfSpace()->getSymbolList();

    auto dl_argv = symbolList->find("_ZN9Emulation8_dl_argvE");
    createDataVariable2(dl_argv->getAddress(), argv, egalito);

    auto environ = symbolList->find("_ZN9Emulation9__environE");
    createDataVariable2(environ->getAddress(), envp, egalito);
}

LoaderEmulator LoaderEmulator::instance;

void LoaderEmulator::setup(Conductor *conductor) {
    const char *functions[] = {
        "_dl_find_dso_for_object",
        "__tunable_get_val",
        "__tunable_set_val",
        "__tls_get_addr"
    };

    this->egalito = conductor->getProgram()->getEgalito();
    auto f = ChunkFind2(conductor).findFunctionInModule(
        "_ZN9Emulation24function_not_implementedEv", egalito);

    for(auto name : functions) {
        addFunction(name, f);
    }

    struct {
        const char *name;
        const char *emulationName;
    } data[] = {
        "_rtld_global",     "_ZN9Emulation12_rtld_globalE",
        "_rtld_global_ro",  "_ZN9Emulation15_rtld_global_roE",
        "_dl_argv",         "_ZN9Emulation8_dl_argvE",
        "__environ",        "_ZN9Emulation9__environE",
        "environ",          "_ZN9Emulation9__environE",
        "_dl_starting_up",  "_ZN9Emulation15_dl_starting_upE",
        "__libc_enable_secure", "_ZN9Emulation20__libc_enable_secureE"
    };

    auto symbolList = egalito->getElfSpace()->getSymbolList();
    for(auto& d : data) {
        auto sym = symbolList->find(d.emulationName);
        auto addr = sym->getAddress();
        addData(d.name, addr);
    }
}

void LoaderEmulator::addFunction(const std::string &symbol,
    Function *function) {

    functionMap[symbol] = function;
}

void LoaderEmulator::addData(const std::string &symbol, address_t address) {
    dataMap[symbol] = address;
}

Function *LoaderEmulator::findFunction(const std::string &symbol) {
    auto it = functionMap.find(symbol);
    return (it != functionMap.end() ? (*it).second : nullptr);
}

Link *LoaderEmulator::makeDataLink(const std::string &symbol,
    bool afterMapping) {

    auto it = dataMap.find(symbol);
    if(it == dataMap.end()) return nullptr;

    auto addr = (*it).second;
    if(afterMapping) {
        addr += egalito->getElfSpace()->getElfMap()->getBaseAddress();
    }

    return LinkFactory::makeDataLink(egalito, addr, true);
}

static void createDataVariable(void *p, Function *target, Module *egalito) {
    address_t addr = reinterpret_cast<address_t>(p);
    auto region = egalito->getDataRegionList()->findRegionContaining(addr);

    auto link = new ExternalNormalLink(target);

    auto var = new DataVariable(region, addr, link);
    region->addVariable(var);
}

void LoaderEmulator::initRT(Conductor *conductor) {
    if(!egalito || !egalito->getElfSpace()) return;
    auto sym = egalito->getElfSpace()->getSymbolList()->find(
        "_ZN9Emulation12_rtld_globalE");
    auto addr = sym->getAddress()
        + egalito->getElfSpace()->getElfMap()->getBaseAddress();
    auto rtld = reinterpret_cast<Emulation::my_rtld_global *>(addr);
    Emulation::init_rtld_global(rtld);

    auto symRo = egalito->getElfSpace()->getSymbolList()->find(
        "_ZN9Emulation15_rtld_global_roE");
    auto addrRo = symRo->getAddress()
        + egalito->getElfSpace()->getElfMap()->getBaseAddress();
    auto rtldRo = reinterpret_cast<Emulation::my_rtld_global_ro *>(addrRo);
    Emulation::init_rtld_global_ro(rtldRo);

    auto f = ChunkFind2(conductor).findFunctionInModule(
        "_ZN9Emulation24function_not_implementedEv", egalito);
    createDataVariable(&rtld->_dl_rtld_lock_recursive, f, egalito);
    createDataVariable(&rtld->_dl_rtld_unlock_recursive, f, egalito);
    createDataVariable(&rtldRo->_dl_lookup_symbol_x, f, egalito);
}
