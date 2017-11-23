#include <iostream>
#include <cstdio>  // for std::fflush
#include <cstdlib>  // for getenv

#include "loader.h"
#include "usage.h"
#include "segmap.h"
#include "emulator.h"
#include "callinit.h"
#include "preparetls.h"
#include "datastruct.h"
#include "elf/auxv.h"
#include "elf/elfmap.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
#include "pass/logcalls.h"
#include "pass/loginstr.h"
#include "pass/noppass.h"
#include "pass/promotejumps.h"
#include "pass/collapseplt.h"
#include "pass/usegstable.h"
#include "pass/jitgsfixup.h"
#include "pass/cancelpush.h"
#include "pass/debloat.h"
#include "runtime/managegs.h"
#include "util/feature.h"
#include "log/registry.h"
#include "log/log.h"

extern address_t entry;
extern const char *initial_stack;
extern "C" void _start2(void);

extern ConductorSetup *egalito_conductor_setup;

EgalitoLoader::EgalitoLoader() {
    this->setup = new ConductorSetup();
    ::egalito_conductor_setup = setup;
}

bool EgalitoLoader::parse(const char *filename) {
    try {
        if(ElfMap::isElf(filename)) {
            LOG(1, "parsing ELF file [" << filename << "]");
            setup->parseElfFiles(filename, true, true);
        }
        else {
            LOG(1, "parsing archive [" << filename << "]");
            setup->parseEgalitoArchive(filename);
        }
    }
    catch(const char *message) {
        std::cout << "Exception: " << message << std::endl;
        return false;
    }

    return true;
}

void EgalitoLoader::setupEnvironment(int *argc, char **argv[]) {
    adjustAuxiliaryVector(*argv, setup->getElfMap(), nullptr);
    auto adjust = removeLoaderFromArgv(*argv);
    initial_stack += adjust;
    *argv = (char **)((char *)*argv + adjust);
    LoaderEmulator::getInstance().useArgv(*argv);
}

void EgalitoLoader::generateCode() {
    SegMap::mapAllSegments(setup);
    setup->getConductor()->handleCopies();
    setup->makeLoaderSandbox(isFeatureEnabled("EGALITO_USE_GS"));
    otherPasses();
    setup->moveCode();
    otherPassesAfterMove();

    setup->getConductor()->fixDataSections();
    setup->getConductor()->writeDebugElf("symbols.elf");
}

void EgalitoLoader::run(int argc, char *argv[]) {
    ::entry = setup->getEntryPoint();
    CLOG(0, "jumping to entry point at 0x%lx", entry);

    std::cout.flush();
    std::fflush(stdout);

    PrepareTLS::prepare(setup->getConductor());

    auto libc = setup->getConductor()->getLibraryList()->getLibc();
    if(libc && libc->getElfSpace()) {
        CallInit::callInitFunctions(libc->getElfSpace(), argv);
    }

    // update vtable pointers to new libegalito code
    DataStructMigrator().migrate(setup);

    // jump to the interpreter/target program (never returns)
    _start2();
}

static GSTable *gsTable;

void EgalitoLoader::otherPasses() {
#ifdef ARCH_AARCH64
    // best if this could be run without injecting egalito
    // this requires a data variable for all code pointer data
    if(isFeatureEnabled("EGALITO_DEBLOAT")) {
        auto program = setup->getConductor()->getProgram();
        RUN_PASS(DebloatPass(program), program);
    }
#endif

    if(isFeatureEnabled("EGALITO_LOG_CALL")) {
        LogCallsPass logCalls(setup->getConductor());
        // false = do not add tracing to Egalito's own functions
        setup->getConductor()->acceptInAllModules(&logCalls, false);
        //setup->getConductor()->getProgram()->getMain()->accept(&logCalls);
    }

#if 1  // add instruction logging?
    if(isFeatureEnabled("EGALITO_LOG_INSTRUCTION_PASS")) {
        RUN_PASS(LogInstructionPass(setup->getConductor()),
            setup->getConductor()->getProgram()->getMain());
    }
#endif

#if 0  // add nop pass
    NopPass nopPass;
    setup->getConductor()->getProgram()->getMain()->accept(&nopPass);
#endif

#if 1
    if(1 || isFeatureEnabled("EGALITO_USE_GS")) {
        CollapsePLTPass collapsePLT;
        setup->getConductor()->acceptInAllModules(&collapsePLT, true);
    }
#endif

#if 1
    if(isFeatureEnabled("EGALITO_USE_GS")) {
        gsTable = new GSTable();
        //setup->getConductor()->getProgram()->getChildren()->add(gsTable);
        UseGSTablePass useGSTable(gsTable);
        setup->getConductor()->acceptInAllModules(&useGSTable, true);

        JitGSFixup jitGSFixup(setup->getConductor(), gsTable);
        setup->getConductor()->getProgram()->accept(&jitGSFixup);
    }
#endif

#ifdef ARCH_X86_64
    PromoteJumpsPass promoteJumps;
    setup->getConductor()->acceptInAllModules(&promoteJumps, true);
#endif

    // enable CollapsePLTPass for better result
    if(isFeatureEnabled("EGALITO_USE_CANCELPUSH")) {
        auto program = setup->getConductor()->getProgram();
        CancelPushPass cancelPush(program);
        program->accept(&cancelPush);
    }
}

void EgalitoLoader::otherPassesAfterMove() {
#if 1
    if(isFeatureEnabled("EGALITO_USE_GS")) {
        ManageGS::init(gsTable);
    }
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
        loader.setupEnvironment(&argc, &argv);
        loader.generateCode();
        loader.run(argc, argv);  // never returns
    }

    return 0;
}
