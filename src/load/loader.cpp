#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdio>  // for std::fflush

#include "usage.h"
#include "segmap.h"
#include "emulator.h"
#include "elf/auxv.h"
#include "elf/elfmap.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
#include "break/signals.h"
#include "pass/logcalls.h"
#include "log/registry.h"
#include "log/log.h"

extern address_t entry;
extern void *main_tp;
extern "C" void _start2(void);

static void mapSegments(ConductorSetup *setup);
static void otherPasses(ConductorSetup *setup);

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printUsage(argv[0]);
        return -1;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        printUsage(argv[0]);
        return -2;
    }
    GroupRegistry::getInstance()->dumpSettings();

    LOG(0, "loading ELF program [" << argv[1] << "]");

    //Signals::registerHandlers();

    LoaderEmulator::getInstance().useArgv(argv);

    try {
        ConductorSetup setup;

        setup.parseElfFiles(argv[1], true, true);
        mapSegments(&setup);
        setup.makeLoaderSandbox();
        otherPasses(&setup);
        setup.moveCode();

        setup.getConductor()->fixDataSections();
        setup.getConductor()->writeDebugElf("symbols.elf");

        entry = setup.getEntryPoint();

        CLOG(0, "jumping to entry point at 0x%lx", entry);

        // set up execution environment
        adjustAuxiliaryVector(argv, setup.getElfMap(), nullptr);

        std::cout.flush();
        std::fflush(stdout);

        // jump to the interpreter/target program (never returns)
        main_tp = setup.getMainThreadPointer();
        _start2();
    }
    catch(const char *s) {
        LOG(0, "ERROR: " << s);
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    return 0;
}

static void mapSegments(ConductorSetup *setup) {
    auto elf = setup->getElfMap();
    auto egalito = setup->getEgalitoElfMap();

    // map PT_LOAD sections into memory
    if(elf) {
        SegMap::mapSegments(*elf, elf->getBaseAddress());
    }
    if(egalito) {
        SegMap::mapSegments(*egalito, egalito->getBaseAddress());
    }

    for(auto lib : *setup->getConductor()->getLibraryList()) {
        auto map = lib->getElfMap();
        if(map) {
            SegMap::mapSegments(*map, map->getBaseAddress());
        }
    }
}

static void otherPasses(ConductorSetup *setup) {
#if 1  // add call logging?
    LogCallsPass logCalls(setup->getConductor());
    // false = do not add tracing to Egalito's own functions
    setup->getConductor()->acceptInAllModules(&logCalls, false);
#endif
}
