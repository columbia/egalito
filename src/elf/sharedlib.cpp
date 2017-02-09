#include "sharedlib.h"

void LibraryList::add(SharedLib *library) {
    auto it = libraryMap.find(library->getFullPath());
    if(it != libraryMap.end()) return;  // already present

    libraryMap[library->getFullPath()] = library;
    libraryList.push_back(library);
}
