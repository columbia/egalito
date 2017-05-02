#include <elf.h>
#include <stdlib.h>  // for realpath() [ARM]
#include <limits.h>  // for PATH_MAX [ARM]
#include <iomanip>
#include <sstream>
#include "elfmap.h"
#include "sharedlib.h"
#include "types.h"
#include "elfxx.h"

std::string SharedLib::getAlternativeSymbolFile() const {
#ifdef ARCH_X86_64
    auto buildIdSection = elfMap->findSection(".note.gnu.build-id");
    if(buildIdSection) {
        auto buildIdHeader = buildIdSection->getHeader();
        auto section = elfMap->getSectionReadPtr<const char *>(buildIdSection);
        auto note = elfMap->getSectionReadPtr<ElfXX_Nhdr *>(buildIdSection);
        auto sectionEnd = reinterpret_cast<const ElfXX_Nhdr *>(section + buildIdHeader->sh_size);
        while(note < sectionEnd) {
            if(note->n_type == NT_GNU_BUILD_ID) {
                const char *p = reinterpret_cast<const char *>(note + 1) + 4;  // +4 to skip "GNU" string

                std::ostringstream symbolFile;
                symbolFile << "/usr/lib/debug/.build-id/";

                for(size_t i = 0; i < note->n_descsz; i ++) {
                    symbolFile << std::setw(2) << std::setfill('0') << std::hex
                        << ((int)p[i] & 0xff);
                    if(i == 0) symbolFile << "/";
                }
                symbolFile << ".debug";

#if 0
                LOG0(3, "        build ID: ");
                for(size_t i = 0; i < note->n_descsz; i ++) {
                    LOG0(3, std::hex << ((int)p[i] & 0xff));
                }
                LOG(3, "");

                LOG(3, symbolFile.str());
#endif
                return symbolFile.str();
            }

            size_t align = ~((1 << buildIdHeader->sh_addralign) - 1);
            note += ((sizeof(*note) + note->n_namesz + note->n_descsz) + (align-1)) & align;
        }
    }
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    std::ostringstream symbolFile;
    symbolFile << "/usr/lib/debug";
    char realPath[PATH_MAX];
    if(realpath(fullPath.c_str(), realPath)) {
        symbolFile << realPath << ".debug";
        return symbolFile.str();
    }
#endif
    return "";
}

void LibraryList::add(SharedLib *library) {
    auto it = libraryMap.find(library->getFullPath());
    if(it != libraryMap.end()) return;  // already present

    libraryMap[library->getFullPath()] = library;
    libraryList.push_back(library);
}

SharedLib *LibraryList::get(const std::string &name) {
    auto it = libraryMap.find(name);
    return (it != libraryMap.end() ? (*it).second : nullptr);
}

#ifndef LIBC_PATH
#define LIBC_PATH   "/lib/x86_64-linux-gnu/libc.so.6"
#endif

SharedLib *LibraryList::getLibc() {
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
