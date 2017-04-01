#include "conductor.h"
#include "elf/elfmap.h"
#include "elf/debugelf.h"
#include "pass/relocdata.h"
#include "transform/data.h"

Conductor::Conductor() {
    libraryList = new LibraryList();
    spaceList = new ElfSpaceList();
}

void Conductor::parseRecursive(ElfMap *elf) {
    parse(elf, nullptr);

    // we use an index here because the list can change as we iterate
    for(size_t i = 0; i < libraryList->getCount(); i ++) {
        auto library = libraryList->get(i);
        parse(library->getElfMap(), library);
    }
}

void Conductor::parse(ElfMap *elf, SharedLib *library) {
    ElfSpace *space = new ElfSpace(elf, library, this);
    if(library) library->setElfSpace(space);
    space->findDependencies(libraryList);
    space->buildDataStructures();
    spaceList->add(space, library == nullptr);
}

void Conductor::parseEgalito(ElfMap *elf, SharedLib *library) {
    ElfSpace *space = new ElfSpace(elf, library, this);
    library->setElfSpace(space);
    space->findDependencies(libraryList);
    space->buildDataStructures();
    spaceList->addEgalito(space);
}

void Conductor::fixDataSections() {
    for(auto library : *libraryList) {
        if(library->getElfSpace()) {
            fixDataSection(library->getElfSpace());
        }
    }

    fixDataSection(spaceList->getMain());

    loadTLSData();
}

void Conductor::fixDataSection(ElfSpace *elfSpace) {
    RelocDataPass relocData(
        elfSpace->getElfMap(),
        elfSpace,
        elfSpace->getRelocList(),
        this);
    elfSpace->getModule()->accept(&relocData);
}

void Conductor::loadTLSData() {
    auto module = getMainSpace()->getModule();
    DataLoader loader;

    mainThreadPointer = loader.setupMainData(module, 0xd0000000);
    int i = 1;
    for(auto lib : *getLibraryList()) {
        if(!lib->getElfSpace()) continue;
        loader.loadLibraryTLSData(
            lib->getElfSpace()->getModule(), 0xd0000000 + i*0x1000000);
        i ++;
    }
}

void Conductor::writeDebugElf(const char *filename, const char *suffix) {
    DebugElf debugElf;

    auto mainModule = getMainSpace()->getModule();
    for(auto func : CIter::functions(mainModule)) {
        debugElf.add(func, suffix);
    }

    for(auto library : *libraryList) {
        if(!library->getElfSpace()) continue;
        auto module = library->getElfSpace()->getModule();
        for(auto func : CIter::functions(module)) {
            debugElf.add(func, suffix);
        }
    }

    debugElf.writeTo(filename);
}

void Conductor::acceptInAllModules(ChunkVisitor *visitor, bool inEgalito) {
    spaceList->getMain()->getModule()->accept(visitor);

    for(auto library : *libraryList) {
        auto space = library->getElfSpace();
        if(!space) continue;
        if(!inEgalito && space == spaceList->getEgalito()) continue;

        if(library->getElfSpace()) {
            library->getElfSpace()->getModule()->accept(visitor);
        }
    }
}
