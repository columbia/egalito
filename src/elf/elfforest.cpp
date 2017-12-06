#include "elfforest.h"

ElfForest::ElfForest() {
    libraryList = new SharedLibList();
    spaceList = new ElfSpaceList();
}

ElfForest::~ElfForest() {
    delete libraryList;
    delete spaceList;
}
