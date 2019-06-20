#include <stdlib.h>  // for realpath() [ARM]
#include <libgen.h>  // for dirname() [ARM]
#include <limits.h>  // for PATH_MAX [ARM]
#include <unistd.h>  // for access()
#include <iomanip>  // for std::setw etc
#include <sstream>  // for ostringstream
#include "exefile.h"
#include "elf/symbol.h"
#include "elf/elfdynamic.h"
#include "pe/symbolparser.h"
#include "dwarf/parser.h"
#include "chunk/concrete.h"
#include "chunk/aliasmap.h"
#include "elf/elfxx.h"
#include "types.h"
#include "conductor/filesystem.h"
#include "log/log.h"

void ElfExeFile::parseSymbolsAndRelocs(const std::string &symbolFile) {
    auto elf = getMap();
    if(symbolFile.size() > 0) {
        setSymbolList(SymbolList::buildSymbolList(elf, symbolFile));
    }
    else if(getFullPath().size() > 0) {
        auto altSymbolFile = getAlternativeSymbolFile();
        setSymbolList(SymbolList::buildSymbolList(elf, altSymbolFile));
    }
    else {
        setSymbolList(SymbolList::buildSymbolList(elf));
    }

    if(!getSymbolList()) {
        DwarfParser dwarfParser(elf);
        this->dwarf = dwarfParser.getUnwindInfo();
    }

    if(elf && elf->isDynamic()) {
        setDynamicSymbolList(SymbolList::buildDynamicSymbolList(elf));
    }

    if(elf) {
        setRelocList(RelocList::buildRelocList(elf,
            getSymbolList(), getDynamicSymbolList()));
    }
}

std::string ElfExeFile::getAlternativeSymbolFile() const {
    auto elf = getMap();
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
                symbolFile << ConductorFilesystem::getInstance()->transform(
                    "/usr/lib/debug/.build-id/");

                for(size_t i = 0; i < note->n_descsz; i ++) {
                    symbolFile << std::setw(2) << std::setfill('0') << std::hex
                        << ((int)p[i] & 0xff);
                    if(i == 0) symbolFile << "/";
                }
                symbolFile << ".debug";

                if(access(symbolFile.str().c_str(), F_OK) == 0) return symbolFile.str();
            }

            size_t align = ~((1 << buildIdHeader->sh_addralign) - 1);
            note += ((sizeof(*note) + note->n_namesz + note->n_descsz) + (align-1)) & align;
        }
    }

    std::ostringstream symbolFile;
    symbolFile << ConductorFilesystem::getInstance()->transform("/usr/lib/debug");
    char realPath[PATH_MAX];
    if(realpath(getFullPath().c_str(), realPath)) {
        auto debuglink = elf->findSection(".gnu_debuglink");
        if(debuglink) {
            auto name = elf->getSectionReadPtr<char *>(debuglink);
            symbolFile << dirname(realPath) << "/" << name;
        }
        else {
            symbolFile << realPath << ".debug";
        }
        if(access(symbolFile.str().c_str(), F_OK) == 0) return symbolFile.str();
    }

    return "";
}

void PEExeFile::parseSymbolsAndRelocs(const std::string &symbolFile) {
    auto pe = getMap();
    if(symbolFile.size() > 0) {
#ifdef USE_WIN64_PE
        setSymbolList(PESymbolParser().buildSymbolList(symbolFile));
#endif
    }
    else {
        //setSymbolList(SymbolList::buildSymbolList(elf));
    }

    /*if(elf && elf->isDynamic()) {
        setDynamicSymbolList(SymbolList::buildDynamicSymbolList(elf));
    }*/

    /*if(elf) {
        setRelocList(RelocList::buildRelocList(elf,
            getSymbolList(), getDynamicSymbolList()));
    }*/
}
