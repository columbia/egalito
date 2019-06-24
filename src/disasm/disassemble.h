#ifndef EGALITO_DISASM_DISASSEMBLE_H
#define EGALITO_DISASM_DISASSEMBLE_H

#include <climits>  // for INT_MIN
#include <capstone/capstone.h>
#include "types.h"
#include "handle.h"
#include "riscv-disas.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "exefile/exefile.h"
#include "dwarf/entry.h"
#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "instr/assembly.h"
#include "instr/storage.h"
#include "disasm/reassemble.h"

class Symbol;
class SymbolList;
class IntervalTree;

class Disassemble {
public:
    static Module *module(ElfExeFile *elfFile);
    static Module *module(PEExeFile *peFile);
    static Module *module(ExeMap *exeMap, SymbolList *symbolList,
        DwarfUnwindInfo *dwarfInfo = nullptr,
        SymbolList *dynamicSymbolList = nullptr,
        RelocList *relocList = nullptr);  // DEPRECATED function
    static Function *function(ExeMap *exeMap, Symbol *symbol,
        SymbolList *symbolList, SymbolList *dynamicSymbolList = nullptr);
    static Instruction *instruction(const std::vector<unsigned char> &bytes,
        bool details = true, address_t address = 0);
    static Instruction *instruction(DisasmHandle &handle,
        const std::vector<unsigned char> &bytes, bool details = true,
        address_t address = 0);
    static Instruction *instruction(cs_insn *ins, DisasmHandle &handle,
        bool details = true);
    #ifdef ARCH_RISCV
    static Instruction *instruction(rv_instr *ins, DisasmHandle &handle,
        bool details = true);
    #endif
    static Assembly makeAssembly(const std::vector<unsigned char> &str,
        address_t address = 0);

private:
    static Module *makeModuleFromSymbols(ExeMap *exeMap,
        SymbolList *symbolList, SymbolList *dynamicSymbolList);
    static Module *makeModuleFromDwarfInfo(ExeMap *exeMap,
        DwarfUnwindInfo *dwarfInfo, SymbolList *dynamicSymbolList,
        RelocList *relocList);
    static FunctionList *linearDisassembly(ExeMap *exeMap,
        const char *sectionName, DwarfUnwindInfo *dwarfInfo,
        SymbolList *dynamicSymbolList, RelocList *relocList);
};

class DisassembleFunctionBase {
protected:
    DisasmHandle &handle;
    ExeMap *exeMap;
public:
    DisassembleFunctionBase(DisasmHandle &handle, ExeMap *exeMap)
        : handle(handle), exeMap(exeMap) {}
protected:
    Block *makeBlock(Function *function, Block *prev);
    void disassembleBlocks(Function *function, char *readAddress,
        size_t readSize, address_t virtualAddress);
    void disassembleCustomBlocks(Function *function, char *readAddress,
        address_t virtualAddress,
        const std::vector<std::pair<address_t, size_t>> &blockBoundaries);

    bool shouldSplitBlockAt(cs_insn *ins);
    #ifdef ARCH_RISCV
    bool shouldSplitBlockAt(rv_instr *ins);
    #endif
    bool shouldSplitFunctionDueTo(cs_insn *ins, address_t *target);
    bool shouldSplitFunctionDueTo2(cs_insn *ins, address_t start,
        address_t end, address_t *target);
};

class DisassembleX86Function : public DisassembleFunctionBase {
public:
    using DisassembleFunctionBase::DisassembleFunctionBase;

    Function *function(Symbol *symbol, SymbolList *symbolList,
        SymbolList *dynamicSymbolList);
    Function *fuzzyFunction(const Range &range, ExeSection *section);
    FunctionList *linearDisassembly(const char *sectionName,
        DwarfUnwindInfo *dwarfInfo, SymbolList *dynamicSymbolList,
        RelocList *relocList);
private:
    void firstDisassemblyPass(ExeSection *section,
        IntervalTree &splitRanges, IntervalTree &functionPadding);
    void disassembleCrtBeginFunctions(ExeSection *section, Range crtbegin,
        IntervalTree &splitRanges);
};

class DisassembleAARCH64Function : public DisassembleFunctionBase {
public:
    using DisassembleFunctionBase::DisassembleFunctionBase;

    Function *function(Symbol *symbol, SymbolList *symbolList);
    FunctionList *linearDisassembly(const char *sectionName,
        DwarfUnwindInfo *dwarfInfo, SymbolList *dynamicSymbolList,
        RelocList *relocList);
private:
    void firstDisassemblyPass(ExeSection *section, IntervalTree &splitRanges);
    void finalDisassemblyPass(ExeSection *section, IntervalTree &splitRanges);
    void splitByDynamicSymbols(SymbolList *dynamicSymbolList,
        IntervalTree &splitRanges);
    void splitByRelocations(RelocList *relocList, IntervalTree &splitRanges);
    Function *fuzzyFunction(const Range &range, ExeSection *section);
    void disassembleBlocks(bool literal, Function *function,
        char *readAddress, size_t readSize, address_t virtualAddress);
    void processLiterals(Function *function, char *readAddress,
        size_t readSize, address_t virtualAddress);

    bool processMappingSymbol(Symbol *symbol);
    bool knownLinkerBytes(Symbol *symbol);
};

class DisassembleRISCVFunction : public DisassembleFunctionBase {
public:
    using DisassembleFunctionBase::DisassembleFunctionBase;

    Function *function(Symbol *symbol, SymbolList *symbolList);
    FunctionList *linearDisassembly(const char *sectionName,
        DwarfUnwindInfo *dwarfInfo, SymbolList *dynamicSymbolList,
        RelocList *relocList);
};

#ifdef ARCH_X86_64
typedef DisassembleX86Function DisassembleFunction;
#elif defined(ARCH_AARCH64)
typedef DisassembleAARCH64Function DisassembleFunction;
#elif defined(ARCH_RISCV)
typedef DisassembleRISCVFunction DisassembleFunction;
#else
#error "need a DisassembleFunction implementation"
#endif

class DisassembleInstruction {
private:
    DisasmHandle &handle;
    bool details;
public:
    DisassembleInstruction(DisasmHandle &handle, bool details = true)
        : handle(handle), details(details) {}

    Instruction *instruction(const std::string &bytes,
        address_t address = 0);
    Instruction *instruction(const std::vector<unsigned char> &bytes,
        address_t address = 0);
    Instruction *instruction(cs_insn *ins);
    #ifdef ARCH_RISCV
    Instruction *instruction(rv_instr *ins);
    #endif
    InstructionSemantic *instructionSemantic(Instruction *instr,
        const std::string &bytes, address_t address = 0);
    InstructionSemantic *instructionSemantic(Instruction *instr,
        const std::vector<unsigned char> &bytes, address_t address = 0);

    Assembly *allocateAssembly(const std::string &bytes,
        address_t address = 0);
    Assembly *allocateAssembly(const std::vector<unsigned char> &bytes,
        address_t address = 0);
    AssemblyPtr makeAssemblyPtr(const std::string &bytes,
        address_t address = 0);
    AssemblyPtr makeAssemblyPtr(const std::vector<unsigned char> &bytes,
        address_t address = 0);
    Assembly makeAssembly(const std::vector<unsigned char> &bytes,
        address_t address = 0);
private:
    #ifndef ARCH_RISCV
    cs_insn *runDisassembly(const uint8_t *bytes, size_t size,
        address_t address);
    #else
    rv_instr *runDisassembly(const uint8_t *bytes, size_t size,
        address_t address);
    #endif
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
