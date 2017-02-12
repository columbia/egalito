#include "dump.h"
#include "log/log.h"

std::string DisasmDump::formatBytes(const char *bytes, size_t size) {
    IF_LOG(10) {
        char buffer[16*3 + 1];
        size_t pos = 0;
        for(size_t i = 0; i < size; i ++) {
            pos += sprintf(buffer + pos, "%02x ", (unsigned)bytes[i] & 0xff);
        }
        return std::string(buffer);
    }

    return std::string();
}

void DisasmDump::printInstruction(cs_insn *instr, int offset,
    const char *name) {

    IF_LOG(9) {} else return;

    // show disassembly of each instruction
    std::string rawDisasm = formatBytes(
        reinterpret_cast<const char *>(instr->bytes), instr->size);

    printInstructionRaw(instr->address, offset, instr->mnemonic,
        instr->op_str, name, rawDisasm);
}

void DisasmDump::printInstructionRaw(unsigned long address, int offset,
    const char *opcode, unsigned long target, const char *name,
    const std::string &rawDisasm) {

    IF_LOG(9) {} else return;

    char targetString[64];
    sprintf(targetString, "0x%lx", target);

    printInstructionRaw(address, offset, opcode, targetString, name, rawDisasm);
}

#define APPEND(...) \
    pos += std::snprintf(buffer + pos, sizeof buffer - pos, __VA_ARGS__)
void DisasmDump::printInstructionRaw(unsigned long address, int offset,
    const char *opcode, const char *args, const char *name,
    const std::string &rawDisasm) {

    IF_LOG(9) {} else return;

    char buffer[1024];
    size_t pos = 0;

    IF_LOG(10) {
        const int displaySize = 10 * 3;
        APPEND("%-*s ", displaySize, rawDisasm.size() ? rawDisasm.c_str() : "---");
    }

    APPEND("0x%08lx", address);

    if(offset != INT_MIN) {
        APPEND(" <+%3d>: ", offset);
    }
    else {
        APPEND(":        ");
    }

    APPEND(" %-12s %-20s", opcode, args);

    if(name) {
        APPEND("<%s>", name);
    }

    std::printf("%s\n", buffer);
}
#undef APPEND
