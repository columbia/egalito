#ifndef EGALITO_DISASM_DISASSEMBLE_H
#define EGALITO_DISASM_DISASSEMBLE_H

#include <climits>  // for INT_MIN
#include <capstone/capstone.h>
#include "types.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "instr/assembly.h"

class Symbol;
class SymbolList;

class Disassemble {
public:
    class Handle {
    private:
        csh handle;
    public:
        Handle(bool detailed = false);
        ~Handle();

        csh &raw() { return handle; }
    };
public:
    static void debug(const uint8_t *code, size_t length,
        address_t realAddress = 0, SymbolList *symbolList = 0);

    static void init();
#if defined(ARCH_ARM) || defined(ARCH_AARCH64)
    static Module *module(ElfMap *elfMap, SymbolList *symbolList, MappingSymbolList *mappingSymbolList=nullptr);
    static Function *function(ElfMap *elfMap, Symbol *symbol, MappingSymbolList *mappingSymbolList=nullptr);
#else
    static Module *module(ElfMap *elfMap, SymbolList *symbolList);
    static Function *function(ElfMap *elfMap, Symbol *symbol);
#endif
    static Assembly makeAssembly(const std::vector<unsigned char> &str,
        address_t address = 0);
    static Instruction *instruction(const std::vector<unsigned char> &bytes,
        bool details = true, address_t address = 0);
    static Instruction *instruction(Handle &handle, const std::vector<unsigned char> &bytes,
                                  bool details = true, address_t address = 0);
    static Instruction *instruction(cs_insn *ins, Handle &handle,
        bool details = true);

    static bool shouldSplitBlockAt(cs_insn *ins, Handle &handle);

private:
    static void disassembleBlock(Handle &handle,
        Function *function, Block **block, address_t readAddress,
        size_t readSize, address_t virtualAddress);
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
