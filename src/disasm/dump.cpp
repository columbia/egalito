#include "dump.h"
#include "handle.h"
#include "instr/assembly.h"
#include "riscv-disas.h"

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

void DisasmDump::printInstruction(address_t address, Assembly *instr, int offset,
    const char *name) {

    IF_LOG(9) {} else return;

    // show disassembly of each instruction
    std::string rawDisasm = formatBytes(instr->getBytes(), instr->getSize());

    printInstructionRaw(address, offset, instr->getMnemonic().c_str(),
        instr->getOpStr().c_str(), name, rawDisasm, false);
}

void DisasmDump::printInstructionCalculated(address_t address, Assembly *instr,
    int offset, unsigned long target) {

    IF_LOG(9) {} else return;

    // show disassembly of each instruction
    std::string rawDisasm = formatBytes(instr->getBytes(), instr->getSize());

    char targetString[64];
    sprintf(targetString, "0x%lx", target);
    printInstructionRaw(address, offset, instr->getMnemonic().c_str(),
        instr->getOpStr().c_str(), targetString, rawDisasm, true);
}

void DisasmDump::printInstructionRaw(unsigned long address, int offset,
    const char *opcode, unsigned long target, bool star, const char *name,
    const std::string &rawDisasm, bool calculatedStyle) {

    IF_LOG(9) {} else return;

    char targetString[64];
    sprintf(targetString, "%s0x%lx", star ? "*" : "", target);

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

    LOG(0, buffer);  // adds newline
}
#undef APPEND

void DisasmDump::printInstructionList(const uint8_t *code, size_t length,
    address_t realAddress, SymbolList *symbolList) {

    DisasmHandle handle(symbolList != 0);
    cs_insn *insn;
    size_t count = cs_disasm(handle.raw(), code, length, realAddress, 0, &insn);
    if(count == 0) {
        CLOG(3, "# empty");
        return;
    }
    for(size_t j = 0; j < count; j++) {
        const char *name = 0;
#ifdef ARCH_X86_64
        if(symbolList && insn[j].id == X86_INS_CALL) {
            cs_x86_op *op = &insn[j].detail->x86.operands[0];
            if(op->type == X86_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        if(symbolList && insn[j].id == ARM64_INS_BL) {
            cs_arm64_op *op = &insn[j].detail->arm64.operands[0];
            if(op->type == ARM64_OP_IMM) {
                unsigned long imm = op->imm;
                auto sym = symbolList->find(imm);
                if(sym) {
                    name = sym->getName();
                }
            }
        }
#endif

        IF_LOG(3) {
            Assembly assembly(insn[j]);
            DisasmDump::printInstruction(
                insn[j].address, &assembly, INT_MIN, name);
        }
    }

    cs_free(insn, count);
}

const char *DisasmDump::getRegisterName(int reg) {
#ifndef ARCH_RISCV
    DisasmHandle handle(true);
    return cs_reg_name(handle.raw(), reg);
#else
    const char *symname = rv_reg_sym(static_cast<rv_reg>(reg));
    return symname;
#endif
}
