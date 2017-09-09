#ifndef EGALITO_DISASM_DISASSEMBLE_H
#define EGALITO_DISASM_DISASSEMBLE_H

#include <climits>  // for INT_MIN
#include <capstone/capstone.h>
#include "types.h"
#include "handle.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "instr/assembly.h"

class Symbol;
class SymbolList;

class Disassemble {
public:
    static void debug(const uint8_t *code, size_t length,
        address_t realAddress = 0, SymbolList *symbolList = 0);

    static void init();
    static Module *module(ElfMap *elfMap, SymbolList *symbolList);
    static Function *linearDisassembly(ElfMap *elfMap,
        const char *sectionName);
    static Function *function(ElfMap *elfMap, Symbol *symbol,
        SymbolList *symbolList);
    static Instruction *instruction(const std::vector<unsigned char> &bytes,
        bool details = true, address_t address = 0);
    static Instruction *instruction(DisasmHandle &handle,
        const std::vector<unsigned char> &bytes, bool details = true,
        address_t address = 0);
    static Instruction *instruction(cs_insn *ins, DisasmHandle &handle,
        bool details = true);

    static Assembly makeAssembly(const std::vector<unsigned char> &str,
        address_t address = 0);

private:
    static Module *makeModuleFromSymbols(ElfMap *elfMap,
        SymbolList *symbolList);
    static Module *makeModuleFromScratch(ElfMap *elfMap);
    static void disassembleBlocks(DisasmHandle &handle, Function *function,
        address_t readAddress, size_t readSize, address_t virtualAddress);
    static void processLiterals(DisasmHandle &handle, Function *function,
        address_t readAddress, size_t readSize, address_t virtualAddress);
    static Block *makeBlock(Function *function, Block *prev);

    static bool shouldSplitBlockAt(cs_insn *ins, DisasmHandle &handle);
    static Symbol *getMappingSymbol(Symbol *symbol);
    static Symbol *findMappingSymbol(SymbolList *symbolList,
        address_t virtualAddress);
    static bool processMappingSymbol(DisasmHandle &handle, Symbol *symbol);
};

class DebugDisassemble {
public:
    static const char *getRegisterName(int reg);
};

class AARCH64InstructionBinary {
private:
    std::vector<unsigned char> v;
public:
    AARCH64InstructionBinary(uint32_t bin)
        : v({static_cast<unsigned char>(bin >> 0  & 0xff),
             static_cast<unsigned char>(bin >> 8  & 0xff),
             static_cast<unsigned char>(bin >> 16 & 0xff),
             static_cast<unsigned char>(bin >> 24 & 0xff)}) {}
    std::vector<unsigned char> getVector() { return v; }
};
#endif
