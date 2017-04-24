#include "conductor.h"
#include "elf/elfmap.h"
#include "generate/debugelf.h"
#include "pass/resolveplt.h"
#include "pass/relocdata.h"
#include "pass/fixjumptables.h"
#include "pass/fixdataregions.h"
#include "pass/libchacks.h"
#include "transform/data.h"
#include "log/log.h"

Conductor::Conductor() {
    forest = new ElfForest();
    program = new Program(forest->getSpaceList());
}

Conductor::~Conductor() {
    delete forest;
    delete program;
}

void Conductor::parseExecutable(ElfMap *elf) {
    parse(elf, nullptr);
}

void Conductor::parseEgalito(ElfMap *elf, SharedLib *library) {
    ElfSpace *space = new ElfSpace(elf, library);
    library->setElfSpace(space);
    space->findDependencies(getLibraryList());
    space->buildDataStructures();
    getSpaceList()->addEgalito(space);
    program->getChildren()->add(space->getModule());
}

void Conductor::parseLibraries() {
    // we use an index here because the list can change as we iterate
    for(size_t i = 0; i < getLibraryList()->getCount(); i ++) {
        auto library = getLibraryList()->get(i);
        if(library->getElfMap() == getSpaceList()->getEgalito()->getElfMap()) {
            continue;
        }
        parse(library->getElfMap(), library);
    }
}

void Conductor::parse(ElfMap *elf, SharedLib *library) {
    ElfSpace *space = new ElfSpace(elf, library);
    if(library) library->setElfSpace(space);
    space->findDependencies(getLibraryList());
    space->buildDataStructures();
    getSpaceList()->add(space, library == nullptr);
    program->getChildren()->add(space->getModule());
}

void Conductor::resolvePLTLinks() {
    ResolvePLTPass resolvePLT(program);
    program->accept(&resolvePLT);

    LibcHacksPass libcHacks(program);
    getLibraryList()->getLibc()->getElfSpace()->getModule()->accept(&libcHacks);
}

void Conductor::fixDataSections() {
    loadTLSData();

    for(auto module : CIter::children(program)) {
        fixDataSection(module);
    }
}

void Conductor::fixDataSection(Module *module) {
    RelocDataPass relocData(module->getElfSpace(), this);
    module->accept(&relocData);

    FixJumpTablesPass fixJumpTables;
    module->accept(&fixJumpTables);

    FixDataRegionsPass fixDataRegions;
    module->accept(&fixDataRegions);
}

void Conductor::loadTLSData() {
#if 0
    auto module = getMainSpace()->getModule();
    DataLoader loader;
    mainThreadPointer = loader.setupMainData(module, 0xd0000000);

    int i = 1;
    for(auto lib : *getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        auto t = loader.loadLibraryTLSData(
            lib->getElfSpace()->getModule(), 0xd0000000 + i*0x1000000);
        i ++;

#ifdef ARCH_X86_64
        if(lib == getLibraryList()->getLibc()) {
            mainThreadPointer = t;
        }
#endif
    }
#else
    auto libc = getLibraryList()->getLibc();
    auto regionList = libc->getElfSpace()->getModule()->getDataRegionList();
    auto region = regionList->getTLS();
    mainThreadPointer = DataLoader(libc->getElfMap())
        .mapTLS(region, 0xd0000000);

    int i = 1;
    for(auto module : CIter::children(program)) {
        if(module == libc->getElfSpace()->getModule()) continue;
        auto tls = module->getDataRegionList()->getTLS();
        if(!tls) continue;

        DataLoader(module->getElfSpace()->getElfMap())
            .mapTLS(tls, 0xd0000000 + i*0x1000000);
        i ++;
    }
#endif
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
        if(inEgalito && module == program->getEgalito()) continue;

        module->accept(visitor);
    }
}
