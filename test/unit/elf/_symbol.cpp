#include "framework/include.h"
#include "exefile/exefile.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"

TEST_CASE("Build Symbol List", "[elf][symbollist]") {
    ElfMap *elf = new ElfMap(TESTDIR "hello");
    ElfExeFile *elfFile = new ElfExeFile(elf, "", "");

    SymbolList *symbolList = SymbolList::buildSymbolList(elf);
    CHECK(symbolList->getCount() > 0);
}

#if defined(ARCH_ARM)
TEST_CASE("Mapping Symbol List ", "[elf][mappingsym]") {
    ElfMap *elf = new ElfMap(TESTDIR "hi5");

    SymbolList *symbolList = SymbolList::buildSymbolList(elf);
    MappingSymbolList *mappingSymbolList = MappingSymbolList::buildMappingSymbolList(symbolList);

    CHECK(mappingSymbolList->getCount() > 0);
}
#endif
