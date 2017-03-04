#include "conductor.h"
#include "elf/elfmap.h"
#include "pass/relocdata.h"

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

void Conductor::fixDataSections() {
    for(auto library : *libraryList) {
        fixDataSection(library->getElfSpace());
    }

    fixDataSection(spaceList->getMain());
}

void Conductor::fixDataSection(ElfSpace *elfSpace) {
    RelocDataPass relocData(
        elfSpace->getElfMap(),
        elfSpace->getRelocList(),
        this);
    elfSpace->getModule()->accept(&relocData);
}
