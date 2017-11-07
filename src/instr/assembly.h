#ifndef EGALITO_INSTR_ASSEMBLY_H
#define EGALITO_INSTR_ASSEMBLY_H

#include <types.h>
#include <string>
#include <vector>

#include <capstone/capstone.h>

class AssemblyOperands {
public:
    enum OperandsMode {
        MODE_UNKNOWN = -1,
        MODE_NONE = 0,
        MODE_REG,
        MODE_IMM,
        MODE_REG_REG,
        MODE_MEM_REG,
        MODE_IMM_REG,
        MODE_IMM_MEM,
        MODE_REG_REG_REG,
        MODE_REG_IMM,
        MODE_REG_MEM,
        MODE_REG_REG_IMM,
        MODE_REG_REG_MEM,
        MODE_REG_MEM_IMM,
        MODE_REG_REG_REG_REG,
        MODE_REG_REG_MEM_IMM,
    };

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
                   insn.detail->arm64.operands + insn.detail->arm64.op_count)
        { overrideCapstone(insn); }
    bool getWriteback() const { return writeback; }
    const cs_arm64_op *getOperands() const { return operands.data(); }
private:
    void overrideCapstone(const cs_insn &insn);
#elif defined(ARCH_ARM)
private:
    bool writeback;
    std::vector<cs_arm_op> operands;

public:
    AssemblyOperands(const cs_insn &insn)
        : op_count(insn.detail->arm.op_count),
        writeback(insn.detail->arm.writeback),
        operands(insn.detail->arm.operands,
            insn.detail->arm.operands + insn.detail->arm.op_count) {}
    bool getWriteback() const { return writeback; }
    const cs_arm_op *getOperands() const { return operands.data(); }
#endif
public:
    AssemblyOperands() {}
    size_t getOpCount() const { return op_count; }
    OperandsMode getMode() const;
};

class Assembly {
public:
    enum ExecutionMode {
        MODE_ARM,
        MODE_THUMB,
        MODE_UNKNOWN
    };

private:
    unsigned int id;
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
        : id(insn.id),
          bytes(insn.bytes, insn.bytes + insn.size),
          mnemonic(insn.mnemonic), operandString(insn.op_str),
          operands(insn),
          regs_read_count(insn.detail->regs_read_count),
          regs_read(insn.detail->regs_read,
                     insn.detail->regs_read + insn.detail->regs_read_count),
          regs_write_count(insn.detail->regs_write_count),
          regs_write(insn.detail->regs_write,
                     insn.detail->regs_write + insn.detail->regs_write_count)
        { overrideCapstone(insn); }

    unsigned int getId() const { return id; }
    size_t getSize() const { return bytes.size(); }
    const char *getBytes() const
        { return reinterpret_cast<const char *>(bytes.data()); }
    const std::string &getMnemonic() const { return mnemonic; }
    const std::string &getOpStr() const { return operandString; }
    const AssemblyOperands *getAsmOperands() const { return &operands; }
    size_t getImplicitRegsReadCount() const { return regs_read_count; }
    const uint8_t *getImplicitRegsRead() const { return regs_read.data(); }
    size_t getImplicitRegsWriteCount() const { return regs_write_count; }
    const uint8_t *getImplicitRegsWrite() const { return regs_write.data(); }

#ifdef ARCH_AARCH64
    bool isPreIndex() const;
    bool isPostIndex() const;
#endif
#ifdef ARCH_ARM
    ExecutionMode getExecutionMode() const
        { return insn.size == 2 ? MODE_THUMB : MODE_ARM; }
#endif

private:
    void overrideCapstone(const cs_insn &insn);
};

#endif
