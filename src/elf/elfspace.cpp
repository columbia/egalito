#include "elfspace.h"
#include "symbol.h"
#include "elfdynamic.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "pass/pcrelative.h"
#include "pass/resolvecalls.h"
#include "pass/resolverelocs.h"
#include "pass/funcptrs.h"
#include "pass/stackxor.h"
#include "log/log.h"

ElfSpace::ElfSpace(ElfMap *elf, SharedLib *library)
    : elf(elf), library(library), module(nullptr),
    symbolList(nullptr), dynamicSymbolList(nullptr), relocList(nullptr),
    pltSection(nullptr) {

}

void ElfSpace::findDependencies(LibraryList *libraryList) {
    ElfDynamic dynamic(libraryList);
    dynamic.parse(elf);
}

void ElfSpace::buildDataStructures(bool hasRelocs) {
    LOG(1, "Building elf data structures for [" << getName() << "]");

    if(library) {
        this->symbolList = SymbolList::buildSymbolList(library);
    }
    else {
        this->symbolList = SymbolList::buildSymbolList(elf);
    }
    this->dynamicSymbolList = SymbolList::buildDynamicSymbolList(elf);

    LOG(1, "");
    LOG(1, "=== Creating internal data structures ===");

    auto baseAddr = elf->getCopyBaseAddress();
    this->module = Disassemble::module(baseAddr, symbolList);

    PCRelativePass pcrelative(elf);
    module->accept(&pcrelative);

    ResolveCalls resolver;
    module->accept(&resolver);

    ChunkDumper dumper;
    //module->accept(&dumper);

    this->relocList = RelocList::buildRelocList(elf, symbolList, dynamicSymbolList);
    PLTSection pltSection(relocList);
    pltSection.parse(elf);

    FuncptrsPass funcptrsPass(relocList);
    module->accept(&funcptrsPass);

    ResolveRelocs resolveRelocs(&pltSection);
    module->accept(&resolveRelocs);

    //module->accept(&dumper);

    //StackXOR stackXOR(0x28);
    //module->accept(&stackXOR);

    //module->accept(&dumper);
}

std::string ElfSpace::getName() const {
    return library ? library->getShortName() : "(executable)";
}

void ElfSpaceList::add(ElfSpace *space, bool isMain) {
    spaceList.push_back(space);
    if(isMain) main = space;
}
