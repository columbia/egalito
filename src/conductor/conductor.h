#ifndef EGALITO_CONDUCTOR_CONDUCTOR_H
#define EGALITO_CONDUCTOR_CONDUCTOR_H

#include "elf/sharedlib.h"
#include "elf/elfspace.h"

class Conductor {
private:
    LibraryList *libraryList;
    ElfSpaceList *spaceList;
public:
    Conductor();

    void parseRecursive(ElfMap *elf);
    void parse(ElfMap *elf, SharedLib *library);

    void fixDataSections();

    ElfSpace *getMainSpace() const { return spaceList->getMain(); }
    LibraryList *getLibraryList() const { return libraryList; }
};

#endif
