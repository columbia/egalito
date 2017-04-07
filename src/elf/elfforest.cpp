#include "elfforest.h"

ElfForest::ElfForest() {
    libraryList = new LibraryList();
    spaceList = new ElfSpaceList();
}

ElfForest::~ElfForest() {
    delete libraryList;
    delete spaceList;
}
