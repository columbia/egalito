#include <iostream>
#include <cstdio>  // for std::fflush
#include <cstdlib>  // for getenv
#include <unistd.h>  // for STDERR_FILENO

#include "loader.h"
#include "usage.h"
#include "segmap.h"
#include "emulator.h"
#include "callinit.h"
#include "preparetls.h"
#include "datastruct.h"
#include "makebridge.h"
#include "chunk/tls.h"
#include "elf/auxv.h"
#include "elf/elfmap.h"
#include "conductor/conductor.h"
#include "conductor/setup.h"
#include "instr/storage.h"
#include "pass/logcalls.h"
#include "pass/loginstr.h"
#include "pass/noppass.h"
#include "pass/promotejumps.h"
#include "pass/resolveplt.h"
#include "pass/collapseplt.h"
#include "pass/hijack.h"
#include "pass/jitgssetup.h"
#include "pass/usegstable.h"
#include "pass/jitgsfixup.h"
#include "pass/cancelpush.h"
#include "pass/retpoline.h"
#include "pass/debloat.h"
#include "pass/makecache.h"
#include "pass/reorderpush.h"
#include "runtime/managegs.h"
#include "transform/sandbox.h"
#include "util/feature.h"
#include "util/timing.h"
#include "cminus/print.h"
#include "log/registry.h"
#include "log/temp.h"
#include "log/log.h"

//EgalitoTiming *m;

extern address_t egalito_entry;
extern const char *egalito_initial_stack;
extern "C" void _start2(void);

extern ConductorSetup *egalito_conductor_setup;

static GSTable *gsTable;

static std::chrono::high_resolution_clock::time_point masterLoadTime;

EgalitoLoader::EgalitoLoader() : sandbox(nullptr) {
    this->setup = new ConductorSetup();
    ::egalito_conductor_setup = setup;
}

bool EgalitoLoader::parse(const char *filename) {
    try {
        if(ElfMap::isElf(filename)) {
            LOG(1, "parsing ELF file [" << filename << "]");
            setup->parseElfFiles(filename, true, true);
            fromArchive = false;
        }
        else {
            LOG(1, "parsing archive [" << filename << "]");
            setup->parseEgalitoArchive(filename);
            fromArchive = true;
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
    LoaderEmulator::getInstance().setStackLinks(argv, envp);

    SegMap::mapAllSegments(setup);
    LoaderEmulator::getInstance().initRT(setup->getConductor());

    // assign addresses of global variables passed-through to target
    MakeLoaderBridge::make();
}

void EgalitoLoader::generateCode() {
    if(isFeatureEnabled("EGALITO_USE_GS")) {
        this->sandbox = setup->makeShufflingSandbox();
    }
    else {
        this->sandbox = setup->makeLoaderSandbox();
    }
    setup->getConductor()->setupIFuncLazySelector();

    otherPasses();
    setup->moveCode(sandbox);
    otherPassesAfterMove();

    setup->getConductor()->fixDataSections();
#ifndef RELEASE_BUILD
    setup->getConductor()->writeDebugElf("symbols.elf");
#endif
}

void EgalitoLoader::run() {
    auto program = setup->getConductor()->getProgram();
    CallInit::makeInitArray(program, argc, argv, envp, gsTable);

    auto entry = setup->getConductor()->getProgram()->getEntryPoint();
    if(isFeatureEnabled("EGALITO_USE_GS")) {
        auto gsEntry = gsTable->makeJITEntryFor(entry);
        ::egalito_entry = gsEntry->getOffset();
        CLOG(0, "entry point at gs@[%ld] = 0x%lx",
             egalito_entry, entry->getAddress());
    }
    else {
        ::egalito_entry = entry->getAddress();
        CLOG(0, "entry point at 0x%lx", egalito_entry);
    }

    auto start2 = CallInit::getStart2(setup->getConductor());

    std::cout.flush();
    std::fflush(stdout);

    // on egalito2, this is needed
    if(!fromArchive) AssemblyFactory::getInstance()->clearCache();

    ShufflingSandbox *shufflingSandbox
        = dynamic_cast<ShufflingSandbox *>(sandbox);

    // --- last point virtual functions work ---
    // update vtable pointers to new libegalito code (LOG needs vtable)
    DataStructMigrator().migrate(setup);

    if(isFeatureEnabled("EGALITO_MEASURE_LOADTIME")) {
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>
            (endTime - masterLoadTime).count();
        egalito_fprintf(egalito_stderr, "load time: %d\n",
            static_cast<int>(duration / 1000));
    }

    // --- last point accesses to loader TLS work ('new' needs loader TLS)
    PrepareTLS::prepare(setup->getConductor());

    if(shufflingSandbox) {
        EgalitoTLS::setSandbox(shufflingSandbox);
        EgalitoTLS::setGSTable(gsTable);
    }

    // jump to the target program (never returns)
    start2();
    //_start2();
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

    if(1 || isFeatureEnabled("EGALITO_USE_GS")) {
        //TemporaryLogLevel tll("pass", 20);

        CollapsePLTPass collapsePLT(setup->getConductor());
        setup->getConductor()->acceptInAllModules(&collapsePLT, true);
    }

    if(isFeatureEnabled("EGALITO_USE_GS")) {
        {
            HijackPass hijackPass(setup->getConductor(), "pthread_create");
            program->getMain()->accept(&hijackPass);
        }

        {
            HijackPass hijackPass(setup->getConductor(), "sigaction");
            program->getMain()->accept(&hijackPass);
        }
    }

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

    if(isFeatureEnabled("EGALITO_USE_REORDERPUSH")) {
        ReorderPush reorderPush;
        program->accept(&reorderPush);
    }

    if(isFeatureEnabled("EGALITO_USE_RETPOLINES")) {
        RetpolinePass retpoline;
        program->accept(&retpoline);
    }

#ifdef ARCH_X86_64
    if(!fromArchive) {
        PromoteJumpsPass promoteJumps;
        setup->getConductor()->acceptInAllModules(&promoteJumps, true);
    }
#endif

    // enable CollapsePLTPass for better result
    if(isFeatureEnabled("EGALITO_USE_CANCELPUSH")) {
        CancelPushPass cancelPush(program);
        program->accept(&cancelPush);
    }
}

void EgalitoLoader::otherPassesAfterMove() {
    if(isFeatureEnabled("EGALITO_USE_GS")) {
        ManageGS::init(gsTable);
        auto sb = dynamic_cast<ShufflingSandbox *>(sandbox);
        sb->flip();
        sb->reopen();
        sb->recreate();
        sb->finalize();

        MakeCachePass makeCachePass;
        for(auto entry : CIter::children(gsTable)) {
            entry->getTarget()->accept(&makeCachePass);
        }
    }
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

    if(isFeatureEnabled("EGALITO_MEASURE_LOADTIME")) {
        masterLoadTime = std::chrono::high_resolution_clock::now();
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
