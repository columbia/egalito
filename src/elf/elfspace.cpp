#include "elfspace.h"
#include "symbol.h"
#include "elfdynamic.h"
#include "dwarf/parser.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "chunk/aliasmap.h"
#include "chunk/tls.h"
#include "chunk/dataregion.h"
#include "disasm/disassemble.h"
#include "pass/fallthrough.h"
#include "pass/splitbasicblock.h"
#include "pass/internalcalls.h"
#include "pass/externalcalls.h"
#include "pass/handlerelocs.h"
#include "pass/handledatarelocs.h"
#include "pass/inferlinks.h"
#include "pass/relocdata.h"
#include "pass/jumptablepass.h"
#include "pass/jumptablebounds.h"
#include "pass/jtoverestimate.h"
#include "analysis/jumptable.h"
#include "log/log.h"

ElfSpace::ElfSpace(ElfMap *elf, SharedLib *library)
    : elf(elf), dwarf(nullptr), library(library), module(nullptr),
    symbolList(nullptr), dynamicSymbolList(nullptr),
    relocList(nullptr), aliasMap(nullptr) {

}

ElfSpace::~ElfSpace() {
    delete elf;
    delete dwarf;
    delete library;
    delete module;
    delete symbolList;
    delete dynamicSymbolList;
    delete relocList;
    delete aliasMap;
}

void ElfSpace::findDependencies(LibraryList *libraryList) {
    ElfDynamic dynamic(libraryList);
    dynamic.parse(elf, library);
}

void ElfSpace::findSymbolsAndRelocs() {
    if(library) {
        this->symbolList = SymbolList::buildSymbolList(library);
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

std::string ElfSpace::getName() const {
    return library ? library->getShortName() : "(executable)";
}
