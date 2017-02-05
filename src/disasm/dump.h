#ifndef EGALITO_DISASM_DUMP_H
#define EGALITO_DISASM_DUMP_H

#include <climits>
#include <string>
#include <capstone/capstone.h>

class DisasmDump {
public:
    static std::string formatBytes(const char *bytes, size_t size);
    static void printInstruction(cs_insn *instr,
        int offset = INT_MIN, const char *name = 0);
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, unsigned long target,
        const char *name = 0, const std::string &rawDisasm = "");
    static void printInstructionRaw(unsigned long address,
        int offset, const char *opcode, const char *args,
        const char *name, const std::string &rawDisasm);
};

#endif
