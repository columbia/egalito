#ifndef EGALITO_DISASM_DISASSEMBLE_H
#define EGALITO_DISASM_DISASSEMBLE_H

#include <climits>  // for INT_MIN
#include <capstone/capstone.h>
#include "types.h"
#include "handle.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "dwarf/entry.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "instr/assembly.h"

class Symbol;
class SymbolList;

// Old disassembly interface, use Disassemble2 instead
class Disassemble {
public:
    static void init();
    static Module *module(ElfMap *elfMap, SymbolList *symbolList,
        DwarfUnwindInfo *dwarfInfo = nullptr);
    static FunctionList *linearDisassembly(ElfMap *elfMap,
        const char *sectionName, DwarfUnwindInfo *dwarfInfo);
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
    static Module *makeModuleFromDwarfInfo(ElfMap *elfMap,
        DwarfUnwindInfo *dwarfInfo);
};

class DisassembleFunctionBase {
protected:
    DisasmHandle &handle;
    ElfMap *elfMap;
public:
    DisassembleFunctionBase(DisasmHandle &handle, ElfMap *elfMap)
        : handle(handle), elfMap(elfMap) {}
protected:
    Block *makeBlock(Function *function, Block *prev);
    void disassembleBlocks(Function *function, address_t readAddress,
        size_t readSize, address_t virtualAddress);

    bool shouldSplitBlockAt(cs_insn *ins);
    bool shouldSplitFunctionDueTo(cs_insn *ins, address_t *target);
};

class DisassembleX86Function : public DisassembleFunctionBase {
public:
    using DisassembleFunctionBase::DisassembleFunctionBase;

    Function *function(Symbol *symbol, SymbolList *symbolList);
    FunctionList *linearDisassembly(const char *sectionName,
        DwarfUnwindInfo *dwarfInfo);
};

class DisassembleAARCH64Function : public DisassembleFunctionBase {
public:
    using DisassembleFunctionBase::DisassembleFunctionBase;

    Function *function(Symbol *symbol, SymbolList *symbolList);
    FunctionList *linearDisassembly(const char *sectionName,
        DwarfUnwindInfo *dwarfInfo);
private:
    void disassembleBlocks(bool literal, Function *function,
        address_t readAddress, size_t readSize, address_t virtualAddress);
    void processLiterals(Function *function, address_t readAddress,
        size_t readSize, address_t virtualAddress);

    Symbol *getMappingSymbol(Symbol *symbol);
    Symbol *findMappingSymbol(SymbolList *symbolList,
        address_t virtualAddress);
    bool processMappingSymbol(Symbol *symbol);
};

#ifdef ARCH_X86_64
typedef DisassembleX86Function DisassembleFunction;
#else
typedef DisassembleAARCH64Function DisassembleFunction;
#endif

class DisassembleInstruction {
private:
    DisasmHandle &handle;
    bool details;
public:
    DisassembleInstruction(DisasmHandle &handle, bool details = true)
        : handle(handle), details(details) {}

    Instruction *instruction(const std::vector<unsigned char> &bytes,
        address_t address = 0);
    Instruction *instruction(cs_insn *ins);

    Assembly makeAssembly(const std::vector<unsigned char> &str,
        address_t address = 0);
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
