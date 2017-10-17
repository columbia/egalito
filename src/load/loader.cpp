#include <iostream>
#include <cstdio>  // for std::fflush

#include "loader.h"
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
#include "pass/loginstr.h"
#include "pass/noppass.h"
#include "pass/promotejumps.h"
#include "log/registry.h"
#include "log/log.h"

extern address_t entry;
extern const char *initial_stack;
extern "C" void _start2(void);

bool EgalitoLoader::parse(const char *filename) {
    try {
        if(ElfMap::isElf(filename)) {
            LOG(1, "parsing ELF file [" << filename << "]");
            setup.parseElfFiles(filename, true, true);
        }
        else {
            LOG(1, "parsing archive [" << filename << "]");
            setup.parseEgalitoArchive(filename);
        }
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
        return false;
    }

    return true;
}

void EgalitoLoader::generateCode() {
    SegMap::mapAllSegments(&setup);
    setup.makeLoaderSandbox();
    otherPasses();
    setup.moveCode();

    setup.getConductor()->fixDataSections();
    setup.getConductor()->writeDebugElf("symbols.elf");
}

void EgalitoLoader::run(int argc, char *argv[]) {
    ::entry = setup.getEntryPoint();
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

void EgalitoLoader::otherPasses() {
#if 0  // add call logging?
    LogCallsPass logCalls(setup.getConductor());
    // false = do not add tracing to Egalito's own functions
    setup.getConductor()->getProgram()->getMain()->accept(&logCalls);
#endif

#if 1  // add instruction logging?
    RUN_PASS(LogInstructionPass(setup.getConductor()), 
        setup.getConductor()->getProgram()->getMain());
#endif

#if 0  // add nop pass
    NopPass nopPass;
    setup.getConductor()->getProgram()->getMain()->accept(&nopPass);
#endif

#ifdef ARCH_X86_64
    PromoteJumpsPass promoteJumps;
    setup.getConductor()->acceptInAllModules(&promoteJumps, true);
#endif
}

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

    const char *program = argv[1];

    EgalitoLoader loader;
    if(loader.parse(program)) {
        loader.generateCode();
        loader.run(argc, argv);  // never returns
    }

    return 0;
}
