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
#include "pass/jitgssetup.h"
#include "pass/usegstable.h"
#include "pass/jitgsfixup.h"
#include "pass/cancelpush.h"
#include "pass/debloat.h"
#include "runtime/managegs.h"
#include "transform/sandbox.h"
#include "util/feature.h"
#include "log/registry.h"
#include "log/log.h"

extern address_t egalito_entry;
extern const char *egalito_initial_stack;
extern "C" void _start2(void);

extern ConductorSetup *egalito_conductor_setup;

static GSTable *gsTable;

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

void EgalitoLoader::setupEnvironment(int argc, char *argv[]) {
    adjustAuxiliaryVector(argv, setup->getElfMap(), nullptr);
    auto adjust = removeLoaderFromArgv(argv);
    egalito_initial_stack += adjust;
    argv = (char **)((char *)argv + adjust);

    char **environ = argv;
    while(*environ) environ ++;
    environ ++;
    this->argc = argc;
    this->argv = argv;
    this->envp = environ;
    LoaderEmulator::getInstance().setArgumentLinks(argv, envp);

    SegMap::mapAllSegments(setup);
    LoaderEmulator::getInstance().initRT(setup->getConductor());
}

void EgalitoLoader::generateCode() {
    setup->makeLoaderSandbox(isFeatureEnabled("EGALITO_USE_GS"));
    setup->getConductor()->setupIFuncLazySelector();

    otherPasses();
    setup->moveCode();
    otherPassesAfterMove();

    setup->getConductor()->fixDataSections();
    setup->getConductor()->writeDebugElf("symbols.elf");
}

void EgalitoLoader::run() {
    auto libc = setup->getConductor()->getLibraryList()->getLibc();
    if(libc && libc->getElfSpace()) {
        CallInit::makeInitArray(libc->getElfSpace(), argc, argv, envp, gsTable);
    }

    auto entry = setup->getConductor()->getProgram()->getEntryPoint();
    if(isFeatureEnabled("EGALITO_USE_GS")) {
        auto gsEntry = gsTable->makeEntryFor(entry);
        ::egalito_entry = gsEntry->getOffset();
        CLOG(0, "entry point at gs@[%ld]", egalito_entry);
    }
    else {
        ::egalito_entry = entry->getAddress();
        CLOG(0, "entry point at 0x%lx", egalito_entry);
    }

    auto start2 = CallInit::getStart2(setup->getConductor());

    std::cout.flush();
    std::fflush(stdout);

    // --- last point accesses to loader TLS work
    PrepareTLS::prepare(setup->getConductor());

    // --- last point virtual functions work ---
    // update vtable pointers to new libegalito code
    DataStructMigrator().migrate(setup);

    // jump to the target program (never returns)
    //_start2();
    start2();
}

void EgalitoLoader::otherPasses() {
    auto program = setup->getConductor()->getProgram();

    // maybe better if run without injecting egalito
    if(isFeatureEnabled("EGALITO_DEBLOAT")) {
        RUN_PASS(DebloatPass(program), program);
    }

    if(isFeatureEnabled("EGALITO_LOG_CALL")) {
        LogCallsPass logCalls(setup->getConductor());
        // false = do not add tracing to Egalito's own functions
        setup->getConductor()->acceptInAllModules(&logCalls, false);
        //setup->getConductor()->getProgram()->getMain()->accept(&logCalls);
    }

#if 1  // add instruction logging?
    if(isFeatureEnabled("EGALITO_LOG_INSTRUCTION_PASS")) {
        RUN_PASS(LogInstructionPass(setup->getConductor()),
            program->getMain());
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

        JitGSSetup jitGSSetup(setup->getConductor(), gsTable);
        program->accept(&jitGSSetup);

        auto ifuncList = setup->getConductor()->getIFuncList();
        UseGSTablePass useGSTable(setup->getConductor(), gsTable, ifuncList);
        program->accept(&useGSTable);

        JitGSFixup jitGSFixup(setup->getConductor(), gsTable);
        program->accept(&jitGSFixup);
    }
#endif

#ifdef ARCH_X86_64
    PromoteJumpsPass promoteJumps;
    setup->getConductor()->acceptInAllModules(&promoteJumps, true);
#endif

    // enable CollapsePLTPass for better result
    if(isFeatureEnabled("EGALITO_USE_CANCELPUSH")) {
        CancelPushPass cancelPush(program);
        program->accept(&cancelPush);
    }
}

void EgalitoLoader::otherPassesAfterMove() {
#if 1
    if(isFeatureEnabled("EGALITO_USE_GS")) {
        ManageGS::init(gsTable);
        setup->getSandboxFlip()->flip();
        // we should be able to delete the old code by now
    }
#endif
}

#include <sys/personality.h>
int main(int argc, char *argv[]) {
    if(argc < 2) {
        printUsage(argv[0]);
        return -1;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        printUsage(argv[0]);
        return -2;
    }

    personality(personality(-1) & ~READ_IMPLIES_EXEC);

    GroupRegistry::getInstance()->dumpSettings();

    LOG(0, "loading ELF program [" << argv[1] << "]");

    const char *program = argv[1];

    EgalitoLoader loader;
    if(loader.parse(program)) {
        loader.setupEnvironment(argc, argv);
        loader.generateCode();
        loader.run();  // never returns
    }

    return 0;
}
