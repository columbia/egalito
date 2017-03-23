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

void DisasmDump::printInstruction(Assembly *instr, int offset,
    const char *name) {

    IF_LOG(9) {} else return;

    // show disassembly of each instruction
    std::string rawDisasm = formatBytes(instr->getBytes(), instr->getSize());

    printInstructionRaw(instr->getAddress(), offset, instr->getMnemonic(),
        instr->getOpStr(), name, rawDisasm, false);
}

void DisasmDump::printInstructionCalculated(Assembly *instr,
    int offset, unsigned long target) {

    IF_LOG(9) {} else return;

    // show disassembly of each instruction
    std::string rawDisasm = formatBytes(instr->getBytes(), instr->getSize());

    char targetString[64];
    sprintf(targetString, "0x%lx", target);
    printInstructionRaw(instr->getAddress(), offset, instr->getMnemonic(),
        instr->getOpStr(), targetString, rawDisasm, true);
}

void DisasmDump::printInstructionRaw(unsigned long address, int offset,
    const char *opcode, unsigned long target, const char *name,
    const std::string &rawDisasm, bool calculatedStyle) {

    IF_LOG(9) {} else return;

    char targetString[64];
    sprintf(targetString, "0x%lx", target);

    printInstructionRaw(address, offset, opcode, targetString, name, rawDisasm,
        calculatedStyle);
}

#define APPEND(...) \
    pos += std::snprintf(buffer + pos, sizeof buffer - pos, __VA_ARGS__)
void DisasmDump::printInstructionRaw(unsigned long address, int offset,
    const char *opcode, const char *args, const char *name,
    const std::string &rawDisasm, bool calculatedStyle) {

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

    APPEND(" %-12s %-26s", opcode, args);

    if(name) {
        if(calculatedStyle) {
            APPEND("# %s", name);
        }
        else {
            APPEND("<%s>", name);
        }
    }

    std::printf("%s\n", buffer);
}
#undef APPEND
