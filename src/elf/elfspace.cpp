#include "elfspace.h"
#include "symbol.h"
#include "elfdynamic.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "chunk/aliasmap.h"
#include "disasm/disassemble.h"
#include "pass/pcrelative.h"
#include "pass/resolvecalls.h"
#include "pass/resolverelocs.h"
#include "pass/funcptrs.h"
#include "pass/inferredptrs.h"
#include "pass/stackxor.h"
#include "pass/relocheck.h"
#include "pass/relocdata.h"
#include "log/log.h"

ElfSpace::ElfSpace(ElfMap *elf, SharedLib *library, Conductor *conductor)
    : elf(elf), library(library), module(nullptr), conductor(conductor),
    symbolList(nullptr), dynamicSymbolList(nullptr), relocList(nullptr),
    pltSection(nullptr), aliasMap(nullptr) {

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
    Disassemble::init();
    this->module = Disassemble::module(baseAddr, symbolList);

    ResolveCalls resolver;
    module->accept(&resolver);

    ChunkDumper dumper;
    //module->accept(&dumper);

    this->relocList = RelocList::buildRelocList(elf, symbolList, dynamicSymbolList);
    PLTSection::parsePLTList(elf, relocList, module);

    FuncptrsPass funcptrsPass(relocList);
    module->accept(&funcptrsPass);

    ResolveRelocs resolveRelocs(module->getPLTList());
    module->accept(&resolveRelocs);

    PCRelativePass pcrelative(elf, relocList);
    module->accept(&pcrelative);

    InferredPtrsPass inferredPtrsPass(elf);
    module->accept(&inferredPtrsPass);

    //module->accept(&dumper);

    //StackXOR stackXOR(0x28);
    //module->accept(&stackXOR);

    //module->accept(&dumper);

    ReloCheckPass checker(relocList);
    module->accept(&checker);

    aliasMap = new FunctionAliasMap(module);
}

std::string ElfSpace::getName() const {
    return library ? library->getShortName() : "(executable)";
}

void ElfSpaceList::add(ElfSpace *space, bool isMain) {
    spaceList.push_back(space);
    if(isMain) main = space;
}

void ElfSpaceList::addEgalito(ElfSpace *space) {
    spaceList.push_back(space);
    egalito = space;
}
