#ifndef EGALITO_DISASM_DUMP_H
#define EGALITO_DISASM_DUMP_H

#include <climits>
#include <string>
#include <disasm/assembly.h>

class DisasmDump {
public:
    static std::string formatBytes(const char *bytes, size_t size);
    static void printInstruction(Assembly *instr,
        int offset = INT_MIN, const char *name = 0);
    static void printInstructionCalculated(Assembly *instr,
        int offset = INT_MIN, unsigned long target = 0);
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, unsigned long target,
        const char *name = 0, const std::string &rawDisasm = "",
        bool calculatedStyle = false);
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, const char *args,
        const char *name, const std::string &rawDisasm,
        bool calculatedStyle);
};

#endif
