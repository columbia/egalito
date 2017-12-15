#include <stdlib.h>  // for realpath() [ARM]
#include <libgen.h>  // for dirname() [ARM]
#include <limits.h>  // for PATH_MAX [ARM]
#include <iomanip>
#include <sstream>
#include <elf.h>
#include "elfspace.h"
#include "elfmap.h"
#include "sharedlib.h"
#include "symbol.h"
#include "elfdynamic.h"
#include "dwarf/parser.h"
#include "chunk/concrete.h"
#include "chunk/aliasmap.h"
#include "elfxx.h"
#include "types.h"
#include "log/log.h"

#include "config.h"

ElfSpace::ElfSpace(ElfMap *elf, const std::string &name,
    const std::string &fullPath) : elf(elf), dwarf(nullptr),
    name(name), fullPath(fullPath), module(nullptr),
    symbolList(nullptr), dynamicSymbolList(nullptr),
    relocList(nullptr), aliasMap(nullptr) {

}

ElfSpace::~ElfSpace() {
    delete elf;
    delete dwarf;
    delete module;
    delete symbolList;
    delete dynamicSymbolList;
    delete relocList;
    delete aliasMap;
}

void ElfSpace::findSymbolsAndRelocs() {
    if(fullPath.size() > 0) {
        auto symbolFile = getAlternativeSymbolFile();
        this->symbolList = SymbolList::buildSymbolList(elf, symbolFile);
    }
    else {
        this->symbolList = SymbolList::buildSymbolList(elf);
    }

    if(!symbolList) {
        DwarfParser dwarfParser(elf);
        this->dwarf = dwarfParser.getUnwindInfo();
    }

    if(elf->isDynamic()) {
        this->dynamicSymbolList = SymbolList::buildDynamicSymbolList(elf);
    }

    this->relocList
        = RelocList::buildRelocList(elf, symbolList, dynamicSymbolList);
}

std::string ElfSpace::getAlternativeSymbolFile() const {
#ifdef USR_LIB_DEBUG_BY_HASH
    auto buildIdSection = elf->findSection(".note.gnu.build-id");
    if(buildIdSection) {
        auto buildIdHeader = buildIdSection->getHeader();
        auto section = elf->getSectionReadPtr<const char *>(buildIdSection);
        auto note = elf->getSectionReadPtr<ElfXX_Nhdr *>(buildIdSection);
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

                return symbolFile.str();
            }

            size_t align = ~((1 << buildIdHeader->sh_addralign) - 1);
            note += ((sizeof(*note) + note->n_namesz + note->n_descsz) + (align-1)) & align;
        }
    }
#elif defined(USR_LIB_DEBUG_BY_NAME)
    std::ostringstream symbolFile;
    symbolFile << "/usr/lib/debug";
    char realPath[PATH_MAX];
    if(realpath(fullPath.c_str(), realPath)) {
        auto debuglink = elf->findSection(".gnu_debuglink");
        if(debuglink) {
            auto name = elf->getSectionReadPtr<char *>(debuglink);
            symbolFile << dirname(realPath) << "/" << name;
        }
        else {
            symbolFile << realPath << ".debug";
        }
        return symbolFile.str();
    }
#else
    #error "Please define one of USR_LIB_DEBUG_BY_{NAME,HASH} in config/*.h"
#endif
    return "";
}
