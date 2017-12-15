#include <elf.h>
#include <stdlib.h>  // for realpath() [ARM]
#include <libgen.h>  // for dirname() [ARM]
#include <limits.h>  // for PATH_MAX [ARM]
#include <iomanip>
#include <sstream>
#include "elfmap.h"
#include "sharedlib.h"
#include "types.h"
#include "elfxx.h"
#include "config.h"

#define DEBUG_GROUP elf
#include "log/log.h"


#if 0
void SharedLibList::add(SharedLib *library) {
    auto it = libraryMap.find(library->getFullPath());
    if(it != libraryMap.end()) return;  // already present

    libraryMap[library->getFullPath()] = library;
    libraryList.push_back(library);
}

void SharedLibList::addToFront(SharedLib *library) {
    auto it = libraryMap.find(library->getFullPath());
    if(it != libraryMap.end()) return;  // already present

    LOG(1, "REALLY INSERTING library " << library->getShortName());

    libraryMap[library->getFullPath()] = library;
    libraryList.insert(libraryList.begin(), library);
}

SharedLib *SharedLibList::get(const std::string &name) {
    auto it = libraryMap.find(name);
    return (it != libraryMap.end() ? (*it).second : nullptr);
}

#ifndef LIBC_PATH
#define LIBC_PATH   "/lib/x86_64-linux-gnu/libc.so.6"
#endif

SharedLib *SharedLibList::getLibc() {
    auto manual = get(LIBC_PATH);
    if(manual) return manual;

    for(auto lib : libraryList) {
        if(lib->getShortName() == "libc.so"
            || lib->getShortName() == "libc.so.6") {

            return lib;
        }
    }

    return nullptr;
}
#undef LIBC_PATH
#endif
