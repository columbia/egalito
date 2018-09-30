#include <cstring>  // for memcpy in generated code
#include <cassert>
#include "config.h"
#include "emulator.h"
#include "chunk/link.h"
#include "chunk/concrete.h"
#include "chunk/tls.h"
#include "elf/elfspace.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
#include "operation/mutator.h"
#include "operation/find2.h"
#include "log/log.h"

extern ConductorSetup *egalito_conductor_setup;
namespace Emulation {
    #include "../dep/rtld/rtld.h"

    struct my_rtld_global _rtld_global;
    struct my_rtld_global_ro _rtld_global_ro;
    char **_dl_argv;
    char **__environ;           // for libc, musl
    int _dl_starting_up = 0;//1;
    int __libc_enable_secure = 1;
    void *__libc_stack_end;
#ifdef ARCH_AARCH64
    uint64_t __stack_chk_guard = 0;
    uint64_t __pointer_chk_guard = 0;
#endif
    void *not_yet_implemented = 0;
    // XXX: Implement glibc compatible DTV instead of obtaining the actual
    // type for __cxxabiv1::__cxa_eh_globals
    struct my__cxa_eh_globals {
        void *caughtExceptions;
        uint32_t uncauseExceptions;
    } cxa_eh_globals_offset;

    // Right now we look these up by DataVariables. To have a DataVariable
    // created, there must be at least one relocation to each variable. This
    // is a way to force a relocation to be created in libegalito.so.
    void *_force_reloc_to_1 = &_rtld_global;
    void *_force_reloc_to_2 = &_rtld_global_ro;

    static void init_rtld_global(struct my_rtld_global *s) {
        using std::memcpy;
        #include "../dep/rtld/rtld_data1.c"
    }
    static void init_rtld_global_ro(struct my_rtld_global_ro *s) {
        using std::memcpy;
        #include "../dep/rtld/rtld_data2.c"
    }

    int function_not_implemented(void) { return 0; }

    // cf. elf/rtld.c (newer glibc may not need this)
    void ** __attribute__((const)) _dl_error_catch_tsd(void) {
        static void *data = nullptr;
        return &data;
    }
    template <typename T> struct typecheck { typedef int type; };
    template <typename T,
        typename typecheck<decltype(T::_dl_error_catch_tsd)>::type = 0>
    void set_dl_error_catch_tsd(T *rtld) {
        rtld->_dl_error_catch_tsd
            = reinterpret_cast<void *>(&Emulation::_dl_error_catch_tsd);
    }
    void set_dl_error_catch_tsd(...) {}


    // cf. elf/dl-tls.c
    void _dl_get_tls_static_info(size_t *sizep, size_t *alignp) {
        *sizep = _rtld_global._dl_tls_static_size;
        *alignp = _rtld_global._dl_tls_static_align;
    }
    // cf. elf/dl-tls.c
    void *_dl_allocate_tls(void *mem) {
        while(!mem);    // poor man's assert (must work in constructor)
        auto conductor = egalito_conductor_setup->getConductor();
        address_t tcb = reinterpret_cast<address_t>(mem);
        conductor->loadTLSDataFor(tcb);
        // we initialize child's EgalitoTLS here using the data structures
        // created by the parent. However, %gs is not set until the child
        // is actually created. (The child has to execute the parent code
        // for some time until %gs is initialized.)
        if(auto child = EgalitoTLS::getChild()) {
            std::memcpy(reinterpret_cast<void *>(tcb - sizeof(EgalitoTLS)),
                child, sizeof(EgalitoTLS));
        }
        return mem;
    }
    // cf. libstdc++-v3/eh_globals.cc
    void *__cxa_get_globals() {
        // there is no way to know the address of specific TLS variable for
        // multi-threaded case for now, because we don't implement DTV yet
        // (the layout of TLS for any dynamically created thread is outside
        // the egalito's control)
        return &cxa_eh_globals_offset;
    }
}

static void createDataVariable2(Symbol *source, void *target,
    Module *egalito) {

    address_t address = source->getAddress();
    address += egalito->getElfSpace()->getElfMap()->getBaseAddress();

    address_t targetAddress = reinterpret_cast<address_t>(target);
    auto link = new StackLink(targetAddress);

    DataVariable::create(egalito, address, link, nullptr);
}

void LoaderEmulator::setStackLinks(char **argv, char **envp) {
    if(!egalito || !egalito->getElfSpace()) return;
    auto symbolList = egalito->getElfSpace()->getSymbolList();

    auto dl_argv = symbolList->find("_ZN9Emulation8_dl_argvE");
    createDataVariable2(dl_argv, argv, egalito);

    auto environ = symbolList->find("_ZN9Emulation9__environE");
    createDataVariable2(environ, envp, egalito);

    // __libc_stack_end doesn't have to be precise
    auto libc_stack_end = symbolList->find("_ZN9Emulation16__libc_stack_endE");
    createDataVariable2(libc_stack_end, argv, egalito);
}

LoaderEmulator LoaderEmulator::instance;

void LoaderEmulator::setup(Conductor *conductor) {
    const char *functions_NI[] = {
        "_dl_find_dso_for_object",
        "__tunable_get_val",
        "__tunable_set_val",
        "__tls_get_addr"
    };

    this->egalito = conductor->getProgram()->getEgalito();
    auto fni = ChunkFind2(conductor).findFunctionInModule(
        "_ZN9Emulation24function_not_implementedEv", egalito);

    for(auto name : functions_NI) {
        addFunction(name, fni);
    }

    struct {
        const char *name;
        const char *emulationName;
    } functions[] = {
        "_dl_get_tls_static_info",
            "_ZN9Emulation23_dl_get_tls_static_infoEPmS0_",
        "_dl_allocate_tls",     "_ZN9Emulation16_dl_allocate_tlsEPv",
        "__cxa_get_globals",    "_ZN9Emulation17__cxa_get_globalsEv",
    };
    for(auto& f : functions) {
        auto emulated = ChunkFind2(conductor).findFunctionInModule(
            f.emulationName, egalito);
        addFunction(f.name, emulated);
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
        "__libc_stack_end", "_ZN9Emulation16__libc_stack_endE",
        "_dl_starting_up",  "_ZN9Emulation15_dl_starting_upE",
        "__libc_enable_secure", "_ZN9Emulation20__libc_enable_secureE",
#ifdef ARCH_AARCH64
        "__stack_chk_guard", "_ZN9Emulation17__stack_chk_guardE",
        "__pointer_chk_guard", "_ZN9Emulation19__pointer_chk_guardE",
#endif
    };
    auto symbolList = egalito->getElfSpace()->getSymbolList();
    for(auto& d : data) {
        auto sym = symbolList->find(d.emulationName);
        auto addr = sym->getAddress();
        addData(d.name, addr);
    }
}

void LoaderEmulator::setupForExecutableGen(Conductor *conductor) {
    const char *ldsoVars[] = {
        "_rtld_global",
        "_rtld_global_ro",
        //"_dl_argv",
        //"__environ",
        //"environ",
        //"__libc_stack_end",
        //"_dl_starting_up",
        //"__libc_enable_secure",
    };
    for(auto sym : ldsoVars) {
        addData(sym, 0);
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
    if(!addr) {
        // special case for static executable generation
        return new LDSOLoaderLink(symbol);
    }
    if(afterMapping) {
        addr += egalito->getElfSpace()->getElfMap()->getBaseAddress();
    }

    return LinkFactory::makeDataLink(egalito, addr, true);
}

DataVariable *LoaderEmulator::findEgalitoDataVariable(const char *name) {
    return egalito->getDataRegionList()->findVariable(name);
}

static void createDataVariable(void *p, Function *target, Module *egalito) {
    address_t addr = reinterpret_cast<address_t>(p);

    auto link = new NormalLink(target, Link::SCOPE_EXTERNAL_DATA);
    DataVariable::create(egalito, addr, link, nullptr);

    LOG(1, "MADE data variable at " << std::hex << addr << " pointing to "
        << link->getTarget()->getName());
}

void LoaderEmulator::initRT(Conductor *conductor) {
    this->egalito = conductor->getProgram()->getEgalito();
    if(!egalito) {
        LOG(1, "WARNING: no libegalito present, cannot provide loader emulation");
        return;
    }
    auto rtld = findEgalitoDataVariable("_ZN9Emulation12_rtld_globalE");
    auto rtld_casted = reinterpret_cast<Emulation::my_rtld_global *>(
        rtld->getDest()->getTargetAddress());
    Emulation::init_rtld_global(rtld_casted);
    Emulation::set_dl_error_catch_tsd(rtld_casted);
    //rtld_casted->_dl_tls_static_size = 0x1000;
#ifdef ARCH_X86_64
    assert(rtld_casted->_dl_tls_static_align == 64);
#elif defined(ARCH_AARCH64)
    assert(rtld_casted->_dl_tls_static_align == 16);
#endif


    auto rtld_ro = findEgalitoDataVariable("_ZN9Emulation15_rtld_global_roE");
    auto rtld_ro_casted = reinterpret_cast<Emulation::my_rtld_global_ro *>(
        rtld_ro->getDest()->getTargetAddress());
    Emulation::init_rtld_global_ro(rtld_ro_casted);

    LOG(1, "initialize rtld_global at " << rtld_casted);
    LOG(1, "initialize rtld_global_ro at " << rtld_ro_casted);

    auto f = ChunkFind2(conductor).findFunctionInModule(
        "_ZN9Emulation24function_not_implementedEv", egalito);
    createDataVariable(&rtld_casted->_dl_rtld_lock_recursive, f, egalito);
    createDataVariable(&rtld_casted->_dl_rtld_unlock_recursive, f, egalito);
    createDataVariable(&rtld_ro_casted->_dl_lookup_symbol_x, f, egalito);
}
