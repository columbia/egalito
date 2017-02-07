#include "elfbuilder.h"
#include "elf/symbol.h"
#include "elf/elfdynamic.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "pass/resolvecalls.h"
#include "pass/resolverelocs.h"
#include "pass/funcptrs.h"
#include "pass/stackxor.h"
#include "log/log.h"

void ElfBuilder::parseElf(ElfMap *elf) {
    elfSpace = new ElfSpace(elf);
}

void ElfBuilder::parseElf(const char *filename) {
    ElfMap *elf = new ElfMap(filename);
    elfSpace = new ElfSpace(elf);
}

void ElfBuilder::findDependencies() {
    ElfDynamic dynamic;
    dynamic.parse(elfSpace->getElfMap());
}

void ElfBuilder::buildDataStructures(bool hasRelocs) {
    auto elf = elfSpace->getElfMap();
    SymbolList *symbolList = SymbolList::buildSymbolList(elf);
    SymbolList *dynamicSymbolList = SymbolList::buildDynamicSymbolList(elf);

    LOG(1, "");
    LOG(1, "=== Creating internal data structures ===");

    auto baseAddr = elf->getCopyBaseAddress();
    Module *module = Disassemble::module(baseAddr, symbolList);
    elfSpace->setModule(module);

    ResolveCalls resolver;
    module->accept(&resolver);

    ChunkDumper dumper;
    module->accept(&dumper);

    RelocList *relocList = RelocList::buildRelocList(elf, symbolList, dynamicSymbolList);
    PLTSection pltSection(relocList);
    pltSection.parse(elf);

    FuncptrsPass funcptrsPass(relocList);
    module->accept(&funcptrsPass);

    ResolveRelocs resolveRelocs(&pltSection);
    module->accept(&resolveRelocs);

    module->accept(&dumper);

    StackXOR stackXOR(0x28);
    module->accept(&stackXOR);
    module->accept(&dumper);
}
