#include "config.h"
#include "conductor.h"
#include "passes.h"
#include "elf/elfmap.h"
#include "generate/debugelf.h"
#include "pass/handlerelocs.h"
#include "pass/handledatarelocs.h"
#include "pass/handlecopyrelocs.h"
#include "pass/injectbridge.h"
#include "chunk/serializer.h"
#include "pass/internalcalls.h"
#include "pass/resolveplt.h"
#include "pass/resolvetls.h"
#include "pass/fixjumptables.h"
#include "pass/fixdataregions.h"
#include "pass/libchacks.h"
#include "pass/relocheck.h"
#include "disasm/objectoriented.h"
#include "transform/data.h"
#include "log/log.h"
#include "log/temp.h"

Conductor::Conductor() {
    forest = new ElfForest();
    program = new Program(forest->getSpaceList());
}

Conductor::~Conductor() {
    delete forest;
    delete program;
}

void Conductor::parseExecutable(ElfMap *elf) {
    auto library = new SharedLib("(executable)", "(executable)", elf);
    getLibraryList()->addToFront(library);
    auto space = parse(elf, library);

    program->setMain(space->getModule());
    getSpaceList()->setMain(space);
}

void Conductor::parseEgalito(ElfMap *elf) {
    auto library = new SharedLib("(egalito)", "(egalito)", elf);
    getLibraryList()->add(library);
    auto space = parse(elf, library);

    program->setEgalito(space->getModule());
    getSpaceList()->setEgalito(space);
}

void Conductor::parseLibraries() {
    // we use an index here because the list can change as we iterate
    for(size_t i = 0; i < getLibraryList()->getCount(); i ++) {
        auto library = getLibraryList()->get(i);
        auto space = library->getElfSpace();

        if(space) continue;  // already parsed (e.g. libegalito, executable)

        parse(library->getElfMap(), library);
    }
}

Module *Conductor::parseAddOnLibrary(ElfMap *elf) {
    auto library = new SharedLib("(addon)", "(addon)", elf);
    getLibraryList()->add(library);
    auto space = parse(elf, library);
    return space->getModule();
}

ElfSpace *Conductor::parse(ElfMap *elf, SharedLib *library) {
    ElfSpace *space = new ElfSpace(elf, library);
    library->setElfSpace(space);

    LOG(1, "\n=== BUILDING ELF DATA STRUCTURES for ["
        << space->getName() << "] ===");
    space->findDependencies(getLibraryList());
    space->findSymbolsAndRelocs();

    LOG(1, "--- RUNNING DEFAULT ELF PASSES for ["
        << space->getName() << "] ---");
    ConductorPasses(this).newElfPasses(space);

    program->getChildren()->add(space->getModule());
    getSpaceList()->add(space);
    return space;
}

void Conductor::parseEgalitoArchive(const char *archive) {
    ChunkSerializer serializer;
    Chunk *newData = serializer.deserialize(archive);

    if(!newData) {
        LOG(1, "Error parsing archive [" << archive << "]");
        return;  // No data present
    }
    else if(auto p = dynamic_cast<Program *>(newData)) {
        LOG(1, "Using full Chunk tree from archive [" << archive << "]");
        this->program = p;
    }
    else {
        LOG(1, "Not using archive, only a subset of the Chunk tree is present");
    }

    ConductorPasses(this).newArchivePasses(program);
}

void Conductor::resolvePLTLinks() {
    ResolvePLTPass resolvePLT(program);
    program->accept(&resolvePLT);

    if(auto libc = getLibraryList()->getLibc()) {
        LibcHacksPass libcHacks(program);
        if(libc->getElfSpace()) {
            libc->getElfSpace()->getModule()->accept(&libcHacks);
        }
        else {
            LOG(1, "WARNING: don't have ElfSpace anymore for LibcHacks...");
        }
    }
}

void Conductor::resolveTLSLinks() {
    ResolveTLSPass resolveTLS;
    program->accept(&resolveTLS);
}

void Conductor::resolveWeak() {
    //TemporaryLogLevel tll("conductor", 10);
    //TemporaryLogLevel tll2("chunk", 10);

    for(auto lib : *getLibraryList()) {
        auto space = lib->getElfSpace();
        if(!space) continue;    // could be nullptr for parse etshell
        auto module = space->getModule();

        if(module->getName() == "module-(egalito)") {
            InjectBridgePass bridge(space->getRelocList());
            module->accept(&bridge);
        }

        // theoretically this should be three passes, but in practice?
        LOG(10, "[[[[1 HandleRelocsWeak]]]]" << module->getName());
        HandleRelocsWeak handleRelocsPass(
            space->getElfMap(), space->getRelocList());
        module->accept(&handleRelocsPass);

        LOG(10, "[[[[2 HandleDataRelocsExternalStrong]]]]" << module->getName());
        HandleDataRelocsExternalStrong pass1(space->getRelocList(), this);
        module->accept(&pass1);

        LOG(10, "[[[[3 HandleDataRelocsInternalWeak]]]]" << module->getName());
        HandleDataRelocsInternalWeak pass2(space->getRelocList());
        module->accept(&pass2);

        LOG(10, "[[[[4 HandleDataRelocsExternalWeak]]]]" << module->getName());
        HandleDataRelocsExternalWeak pass3(space->getRelocList(), this);
        module->accept(&pass3);
    }
}

void Conductor::resolveVTables() {
    for(auto module : CIter::children(program)) {
#ifdef ARCH_X86_64
        // this needs data regions
        module->setVTableList(DisassembleVTables().makeVTableList(
            module->getElfSpace()->getElfMap(),
            module->getElfSpace()->getSymbolList(),
            module->getElfSpace()->getRelocList(), module, program));
#endif
    }
}

void Conductor::handleCopies() {
    HandleCopyRelocs handleCopyRelocs(this);
    program->accept(&handleCopyRelocs);
}

void Conductor::fixDataSections() {
    // first assign an effective address to each TLS region
    allocateTLSArea();

    fixPointersInData();

    // This has to come after all relocations in TLS are resolved
    loadTLSData();
}

void Conductor::fixPointersInData() {
    FixJumpTablesPass fixJumpTables;
    program->accept(&fixJumpTables);

    FixDataRegionsPass fixDataRegions;
    program->accept(&fixDataRegions);
}

void Conductor::allocateTLSArea() {
    const static address_t base = 0xd0000000;
    DataLoader dataLoader(base);

    // calculate size
    size_t size = 0;
    for(auto module : CIter::children(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) size += tls->getSize();
    }

    if(!size) return;

    // allocate headers
    address_t offset = 0;
    mainThreadPointer = dataLoader.allocateTLS(size, &offset);

    // actually assign address
    for(auto module : CIter::children(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
#ifdef ARCH_X86_64
            if(module == program->getMain()) continue;
#endif
            tls->setBaseAddress(base + offset);
            tls->setTLSOffset((base + offset) - mainThreadPointer);
            offset += tls->getSize();
        }
    }

#ifdef ARCH_X86_64
    // x86: place executable's TLS (if present) right before the header
    auto executable = program->getMain();
    if(auto tls = executable->getDataRegionList()->getTLS()) {
        tls->setBaseAddress(base + offset);
        tls->setTLSOffset((base + offset) - mainThreadPointer);
        offset += tls->getSize();
    }
#endif
}

void Conductor::loadTLSData() {
    const static address_t base = 0xd0000000;
    DataLoader dataLoader(base);
    for(auto module : CIter::children(program)) {
        auto tls = module->getDataRegionList()->getTLS();
        if(tls) {
            dataLoader.loadRegion(module->getElfSpace()->getElfMap(), tls);
        }
    }
}

void Conductor::writeDebugElf(const char *filename, const char *suffix) {
    DebugElf debugElf;

    for(auto module : CIter::children(program)) {
        for(auto func : CIter::functions(module)) {
            debugElf.add(func, suffix);
        }
    }

    debugElf.writeTo(filename);
}

void Conductor::acceptInAllModules(ChunkVisitor *visitor, bool inEgalito) {
    for(auto module : CIter::children(program)) {
        if(!inEgalito && module == program->getEgalito()) continue;

        module->accept(visitor);
    }
}

void Conductor::check() {
    ReloCheckPass checker;
    acceptInAllModules(&checker, true);
}
