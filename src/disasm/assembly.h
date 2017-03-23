#ifndef EGALITO_DISASM_ASSEMBLY_H
#define EGALITO_DISASM_ASSEMBLY_H

#include <types.h>
#include <string>
#include <vector>

#include <capstone/capstone.h>
#ifdef ARCH_X86_64
#elif defined(ARCH_AARCH64)
#include <capstone/arm64.h>
#endif

class MachineAssembly {
private:
    uint8_t op_count;

#ifdef ARCH_X86_64
private:
    std::vector<cs_x86_op> operands;

public:
    MachineAssembly(const cs_insn &insn)
        : op_count(insn.detail->x86.op_count),
          operands(insn.detail->x86.operands,
                   insn.detail->x86.operands + insn.detail->x86.op_count) {}
    const cs_x86_op *getOperands() const { return operands.data(); }
#elif defined(ARCH_AARCH64)
private:
    //arm64_cc cc;
    //bool update_flags;
    bool writeback;
    std::vector<cs_arm64_op> operands;

public:
    MachineAssembly(const cs_insn &insn)
        : op_count(insn.detail->arm64.op_count),
          writeback(insn.detail->arm64.writeback),
          operands(insn.detail->arm64.operands,
                   insn.detail->arm64.operands + insn.detail->arm64.op_count) {}
    bool getWriteback() const { return writeback; }
    const cs_arm64_op *getOperands() const { return operands.data(); }
#endif
public:
    MachineAssembly() {}
    size_t getOpCount() const { return op_count; }
};

class Assembly {
private:
    unsigned int id;
    address_t address;
    size_t size;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string operandString;
    MachineAssembly machine;

    size_t regs_read_count;             // implicit read is not being used
    std::vector<uint8_t> regs_read;     // effectively?
    size_t regs_write_count;
    std::vector<uint8_t> regs_write;

public:
    Assembly() {}
    Assembly(const cs_insn &insn)
        : id(insn.id), address(insn.address), size(insn.size),
          bytes(insn.bytes, insn.bytes + insn.size),
          mnemonic(insn.mnemonic), operandString(insn.op_str),
          machine(insn),
          regs_write_count(insn.detail->regs_write_count),
          regs_write(insn.detail->regs_write,
                     insn.detail->regs_write + insn.detail->regs_write_count) {}

    unsigned int getId() const { return id; }
    address_t getAddress() const { return address; }
    void setAddress(address_t address) { this->address = address; }
    size_t getSize() const { return size; }
    const char *getBytes() const {
        return reinterpret_cast<const char *>(bytes.data()); }
    const char *getMnemonic() const { return mnemonic.c_str(); }
    const char *getOpStr() const { return operandString.c_str(); }
    const MachineAssembly *getMachineAssembly() const { return &machine; }
    size_t getImplicitRegsReadCount() const { return regs_read_count; }
    const uint8_t *getImplicitRegsRead() const { return regs_read.data(); }
    size_t getImplicitRegsWriteCount() const { return regs_write_count; }
    const uint8_t *getImplicitRegsWrite() const { return regs_write.data(); }
};

#endif

