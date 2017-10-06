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

void ElfSpace::buildDataStructures(bool hasRelocs) {
    LOG(1, "");
    LOG(1, "=== BUILDING ELF DATA STRUCTURES for [" << getName() << "] ===");

    if(library) {
        this->symbolList = SymbolList::buildSymbolList(library);
    }
    else {
        this->symbolList = SymbolList::buildSymbolList(elf);
    }

    if(!this->symbolList) {
        DwarfParser dwarfParser(elf);
        this->dwarf = dwarfParser.getUnwindInfo();
    }

    if(elf->isDynamic()) {
        this->dynamicSymbolList = SymbolList::buildDynamicSymbolList(elf);
    }

    this->relocList
        = RelocList::buildRelocList(elf, symbolList, dynamicSymbolList);

    this->module = Disassemble::module(elf, symbolList, dwarf,
        dynamicSymbolList, relocList);
    this->module->setElfSpace(this);

    //ChunkDumper dumper;
    //module->accept(&dumper);

    RUN_PASS(FallThroughFunctionPass(), module);

    DataRegionList::buildDataRegionList(elf, module);

    PLTList::parsePLTList(elf, relocList, module);

    // this needs data regions
    RUN_PASS(HandleDataRelocsInternalStrong(relocList), module);
    RUN_PASS(HandleRelocsStrong(elf, relocList), module);
    RUN_PASS(InternalCalls(), module);

    if(module->getPLTList()) {
        RUN_PASS(ExternalCalls(module->getPLTList()), module);
    }

    RUN_PASS(JumpTablePass(), module);
    RUN_PASS(JumpTableBounds(), module);
    RUN_PASS(JumpTableOverestimate(), module);

    // this needs jumptable information and all NormalLinks
    RUN_PASS(SplitBasicBlock(), module);

    // this needs all blocks to be split to basic blocks
    RUN_PASS(InferLinksPass(elf), module);

    aliasMap = new FunctionAliasMap(module);
}

std::string ElfSpace::getName() const {
    return library ? library->getShortName() : "(executable)";
}
