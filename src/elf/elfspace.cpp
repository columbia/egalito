#include <stdlib.h>  // for realpath() [ARM]
#include <libgen.h>  // for dirname() [ARM]
#include <limits.h>  // for PATH_MAX [ARM]
#include <unistd.h>  // for access()
#include <string.h>  // for strdup()
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
#include "conductor/filesystem.h"
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


bool ElfSpace::shouldTryAlternativeSymbolFile() {
    const char *envp = getenv("EGALITO_DONT_LOAD_SYMBOLS");
    if (!envp) return true;

    std::string env = envp;
    if (env == "") return true;

    const std::set<std::string> alwaysLoad = {
	// Packages in libc6
	"libc.so.6",
	"libanl.so.1",
	"libdl.so.2",
	"libm.so.6",
	"libmvec.so.1",
	"libnsl.so.1",
	"libnss_compat.so.2",
	"libnss_dns.so.2",
	"libnss_files.so.2",
	"libnss_hesiod.so.2",
	"libnss_nis.so.2",
	"libnss_nisplus.so.2",
	"libpthread.so.0",
	"libresolv.so.2",
	"librt.so.1",
	"libthread_db.so.1",
	"libutil.so.1",

	// Package
	"libgnutls.so.30",
	"libffi.so.6",
	"libcrypto.so.1.1",
	"libgcrypt.so.20",
	"libgnutls.so.30",
    };

    if (env == "1") {
        if (alwaysLoad.count(name)) {
	    return true;
	} else {
	    return false;
	}
    } else {
	return true;
    }
}

void ElfSpace::findSymbolsAndRelocs() {
    bool loadExternalSymbols = shouldTryAlternativeSymbolFile();

    if (!loadExternalSymbols) {
	LOG(1, "Loading of external symbol files disabled, not searching for " << name);
    }

    if(loadExternalSymbols && (fullPath.size() > 0)) {
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
    char *realPath = realpath(fullPath.c_str(), NULL);
    if(realPath) {
        std::string untransformed =
            ConductorFilesystem::getInstance()->untransform(realPath);
        auto debuglink = elf->findSection(".gnu_debuglink");
        if(debuglink) {
            char *utc = strdup(untransformed.c_str());
            auto name = elf->getSectionReadPtr<char *>(debuglink);
            symbolFile << dirname(utc) << "/" << name;
            free(utc);
        }
        else {
            symbolFile << realPath << ".debug";
        }

        free(realPath);
        if(access(symbolFile.str().c_str(), F_OK) == 0) return symbolFile.str();

    }

    return "";
}
