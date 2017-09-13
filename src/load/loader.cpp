#include <iostream>
#include <iomanip>
#include <cstring>
#include <cstdio>  // for std::fflush

#include "usage.h"
#include "segmap.h"
#include "emulator.h"
#include "callinit.h"
#include "preparetls.h"
#include "elf/auxv.h"
#include "elf/elfmap.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
#include "pass/logcalls.h"
#include "pass/promotejumps.h"
#include "pass/relocheck.h"
#include "log/registry.h"
#include "log/log.h"

extern address_t entry;
extern const char *initial_stack;
extern "C" void _start2(void);

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

    try {
        ConductorSetup setup;

        setup.parseElfFiles(argv[1], true, true);
        SegMap::mapAllSegments(&setup);
        setup.makeLoaderSandbox();
        otherPasses(&setup);
        Function *entryFunction = setup.getEntryFunction();
        setup.moveCode();

        setup.getConductor()->fixDataSections();
        setup.getConductor()->writeDebugElf("symbols.elf");

        ReloCheckPass checker;
        setup.getConductor()->acceptInAllModules(&checker, true);

        entry = setup.getEntryPoint();

        if(entry == 0 && entryFunction != nullptr) {
            entry = entryFunction->getAddress();
            LOG(0, "Using entry function [" << entryFunction->getName()
                << "]");
        }

        CLOG(0, "jumping to entry point at 0x%lx", entry);

        // set up execution environment
        adjustAuxiliaryVector(argv, setup.getElfMap(), nullptr);
        auto adjust = removeLoaderFromArgv(argv);
        initial_stack += adjust;
        argv = (char **)((char *)argv + adjust);
        LoaderEmulator::getInstance().useArgv(argv);

        auto libc = setup.getConductor()->getLibraryList()->getLibc();
        std::cout.flush();
        std::fflush(stdout);

        PrepareTLS::prepare(setup.getConductor());

        if(libc && libc->getElfSpace()) {
            CallInit::callInitFunctions(libc->getElfSpace(), argv);
        }

        // jump to the interpreter/target program (never returns)
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

static void otherPasses(ConductorSetup *setup) {
#if 0  // add call logging?
    LogCallsPass logCalls(setup->getConductor());
    // false = do not add tracing to Egalito's own functions
    setup->getConductor()->acceptInAllModules(&logCalls, false);
#endif

#ifdef ARCH_X86_64
    PromoteJumpsPass promoteJumps;
    setup->getConductor()->acceptInAllModules(&promoteJumps, true);
#endif
}
