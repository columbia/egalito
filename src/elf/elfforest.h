#ifndef EGALITO_ELF_FOREST_H
#define EGALITO_ELF_FOREST_H

#include "sharedlib.h"
#include "elfspace.h"

class ElfForest {
private:
    SharedLibList *libraryList;
    ElfSpaceList *spaceList;
public:
    ElfForest();
    ~ElfForest();

    SharedLibList *getLibraryList() const { return libraryList; }
    ElfSpaceList *getSpaceList() const { return spaceList; }
    ElfSpace *getMainSpace() const { return spaceList->getMain(); }
};

#endif
