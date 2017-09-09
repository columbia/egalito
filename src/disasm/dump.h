#ifndef EGALITO_DISASM_DUMP_H
#define EGALITO_DISASM_DUMP_H

#include <climits>
#include <string>
#include "types.h"
#include "elf/symbol.h"

class Assembly;

class DisasmDump {
public:
    static std::string formatBytes(const char *bytes, size_t size);
    static void printInstruction(address_t address, Assembly *instr,
        int offset = INT_MIN, const char *name = 0);
    static void printInstructionCalculated(address_t address, Assembly *instr,
        int offset = INT_MIN, unsigned long target = 0);
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, unsigned long target,
        const char *name = 0, const std::string &rawDisasm = "",
        bool calculatedStyle = false);
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, const char *args,
        const char *name, const std::string &rawDisasm,
        bool calculatedStyle);

    static void printInstructionList(const uint8_t *code, size_t length,
        address_t realAddress = 0, SymbolList *symbolList = 0);
    static const char *getRegisterName(int reg);
};

#endif
