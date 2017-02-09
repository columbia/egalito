#include "conductor.h"
#include "elf/elfmap.h"

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
    ElfSpace *space = new ElfSpace(elf, library);
    space->findDependencies(libraryList);
    space->buildDataStructures();
    spaceList->add(space, library == nullptr);
}
