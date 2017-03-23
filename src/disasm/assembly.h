#ifndef EGALITO_DISASM_ASSEMBLY_H
#define EGALITO_DISASM_ASSEMBLY_H

#include <types.h>
#include <string>
#include <vector>

#include <capstone/capstone.h>

class AssemblyOperands {
private:
    uint8_t op_count;

#ifdef ARCH_X86_64
private:
    std::vector<cs_x86_op> operands;

public:
    AssemblyOperands(const cs_insn &insn)
        : op_count(insn.detail->x86.op_count),
          operands(insn.detail->x86.operands,
                   insn.detail->x86.operands + insn.detail->x86.op_count) {}
    const cs_x86_op *getOperands() const { return operands.data(); }
#elif defined(ARCH_AARCH64)
private:
    bool writeback;
    std::vector<cs_arm64_op> operands;

public:
    AssemblyOperands(const cs_insn &insn)
        : op_count(insn.detail->arm64.op_count),
          writeback(insn.detail->arm64.writeback),
          operands(insn.detail->arm64.operands,
                   insn.detail->arm64.operands + insn.detail->arm64.op_count) {}
    bool getWriteback() const { return writeback; }
    const cs_arm64_op *getOperands() const { return operands.data(); }
#endif
public:
    AssemblyOperands() {}
    size_t getOpCount() const { return op_count; }
};

class Assembly {
private:
    unsigned int id;
    size_t size;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string operandString;
    AssemblyOperands operands;

    size_t regs_read_count;             // implicit read is not being used
    std::vector<uint8_t> regs_read;     // effectively?
    size_t regs_write_count;
    std::vector<uint8_t> regs_write;

public:
    Assembly() {}
    Assembly(const cs_insn &insn)
        : id(insn.id), size(insn.size),
          bytes(insn.bytes, insn.bytes + insn.size),
          mnemonic(insn.mnemonic), operandString(insn.op_str),
          operands(insn),
          regs_write_count(insn.detail->regs_write_count),
          regs_write(insn.detail->regs_write,
                     insn.detail->regs_write + insn.detail->regs_write_count) {}

    unsigned int getId() const { return id; }
    size_t getSize() const { return size; }
    const char *getBytes() const {
        return reinterpret_cast<const char *>(bytes.data()); }
    const char *getMnemonic() const { return mnemonic.c_str(); }
    const char *getOpStr() const { return operandString.c_str(); }
    const AssemblyOperands *getAsmOperands() const { return &operands; }
    size_t getImplicitRegsReadCount() const { return regs_read_count; }
    const uint8_t *getImplicitRegsRead() const { return regs_read.data(); }
    size_t getImplicitRegsWriteCount() const { return regs_write_count; }
    const uint8_t *getImplicitRegsWrite() const { return regs_write.data(); }
};

#endif

