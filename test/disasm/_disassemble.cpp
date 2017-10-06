#include <cstring>
#include <capstone/capstone.h>

#include "framework/include.h"
#include "disasm/disassemble.h"
#include "dwarf/parser.h"
#include "chunk/module.h"
#include "chunk/dump.h"
#include "elf/symbol.h"
#include "elf/elfspace.h"
#include "elf/elfmap.h"
#include "instr/isolated.h"

TEST_CASE("Disassemble Instructions", "[disasm][ins]") {
    Instruction *ins = nullptr;

#ifdef ARCH_X86_64

    // add #0, %eax
    std::vector<uint8_t> bytes = {0x83, 0xc0, 0x00};
    ins = Disassemble::instruction(bytes, true, 0);

#elif defined(ARCH_AARCH64)

    // add X0, X0, #0
    std::vector<uint8_t> bytes = {0x00, 0x00, 0x00, 0x91};
    ins = Disassemble::instruction(bytes, true, 0);

#elif defined(ARCH_ARM)
    std::vector<uint8_t> bytes;
    Disassemble::Handle handle(true); 
    // Catch Bug: If attempt to run individually using -c flag => first section will fail.
    SECTION("THUMB") {
        // THUMB: bx r0
        bytes = {0x00, 0x47};
        cs_option(handle.raw(), CS_OPT_MODE, CS_MODE_THUMB);
        ins = Disassemble::instruction(handle, bytes, true, 0);
    }

    SECTION("ARM") {
        // ARM: add r0, r0, #0
        bytes = {0x00, 0x00, 0x80, 0xe2};
        cs_option(handle.raw(), CS_OPT_MODE, CS_MODE_ARM);
        ins = Disassemble::instruction(handle, bytes, true, 0);
    }
#endif

    DisassembledInstruction *disasmIns = static_cast<DisassembledInstruction *>(ins->getSemantic());

    const char *expectedBytes = reinterpret_cast<const char *>(bytes.data());
    const char *actualBytes = disasmIns->getAssembly()->getBytes();

    CHECK(std::memcmp(expectedBytes, actualBytes, bytes.size()) == 0);
}

TEST_CASE("Disassemble Module", "[disasm][module]") {
    ElfMap *elf = new ElfMap(TESTDIR "hi5");

    SymbolList *symbolList = SymbolList::buildSymbolList(elf);

#if defined(ARCH_ARM)
    MappingSymbolList *mappingSymbolList = MappingSymbolList::buildMappingSymbolList(symbolList);
    Module *module = Disassemble::module(elf, symbolList, mappingSymbolList);
#else
    Module *module = Disassemble::module(elf, symbolList);
#endif
    FunctionList *functionList = module->getFunctionList();

    CHECK(functionList->getChildren()->genericGetSize() > 0);
}

TEST_CASE("Fuzzy-function disassemble", "[disasm]") {
    ElfMap *elfWithSymbols = new ElfMap(TESTDIR "hello");
    SymbolList *symbolList = SymbolList::buildSymbolList(elfWithSymbols);
    Symbol *mainSymbol = symbolList->find("main");
    REQUIRE(mainSymbol != nullptr);

    ElfMap *strippedElf = new ElfMap(TESTDIR "hello-s");
    SymbolList *strippedSymbolList = SymbolList::buildSymbolList(strippedElf);
    CHECK(strippedSymbolList->getCount() == 0);
    SymbolList *dynamicSymbolList = nullptr;
    RelocList *relocList = nullptr;
#ifdef ARCH_AARCH64
    dynamicSymbolList = SymbolList::buildDynamicSymbolList(strippedElf);
    relocList = RelocList::buildRelocList(
        strippedElf, strippedSymbolList, dynamicSymbolList);
#endif

    DwarfParser dwarfParser(strippedElf);
    Module *module = Disassemble::module(strippedElf, nullptr,
        dwarfParser.getUnwindInfo(), dynamicSymbolList, relocList);

    Function *fuzzy = CIter::spatial(module->getFunctionList())
        ->find(mainSymbol->getAddress());

    CHECK(mainSymbol->getSize() == fuzzy->getSize());
}
