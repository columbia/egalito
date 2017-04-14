#include "conductor.h"
#include "elf/elfmap.h"
#include "generate/debugelf.h"
#include "pass/resolveplt.h"
#include "pass/relocdata.h"
#include "pass/fixjumptables.h"
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
}

void Conductor::fixDataSections() {
    for(auto module : CIter::children(program)) {
        fixDataSection(module->getElfSpace());
    }

    loadTLSData();
}

void Conductor::fixDataSection(ElfSpace *elfSpace) {
    RelocDataPass relocData(
        elfSpace->getElfMap(),
        elfSpace,
        elfSpace->getRelocList(),
        this);
    elfSpace->getModule()->accept(&relocData);

    FixJumpTablesPass fixJumpTables;
    elfSpace->getModule()->accept(&fixJumpTables);
}

void Conductor::loadTLSData() {
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
