#ifndef EGALITO_INSTR_CONCRETE_H
#define EGALITO_INSTR_CONCRETE_H

#include "semantic.h"
#include "register.h"

#include "isolated.h"

#include "linked-x86_64.h"
#include "linked-aarch64.h"
#include "linked-arm.h"

class ReturnInstruction : public IsolatedInstruction {
public:
    using IsolatedInstruction::IsolatedInstruction;

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class JumpTable;
class IndirectJumpInstruction : public IsolatedInstruction {
private:
    Register reg;
    std::string mnemonic;
    bool memory;
    Register index; // only relevant if memory
    size_t scale;   // only relevant if memory
    int64_t displacement;   // only relevant if memory
    std::vector<JumpTable *> jumpTables;
public:
    IndirectJumpInstruction(const Assembly &assembly, Register reg,
        const std::string &mnemonic)
        : IsolatedInstruction(assembly), reg(reg), mnemonic(mnemonic),
        memory(false), index(INVALID_REGISTER), scale(1),
        displacement(0) {}

    IndirectJumpInstruction(const Assembly &assembly, Register reg,
        const std::string &mnemonic, Register index,
        size_t scale, int64_t displacement)
        : IsolatedInstruction(assembly), reg(reg), mnemonic(mnemonic),
        memory(true), index(index), scale(scale),
        displacement(displacement) {}

    std::string getMnemonic() const { return mnemonic; }
    Register getRegister() const { return reg; }
    bool hasMemoryOperand() const { return memory; }
    Register getIndexRegister() const { return index; }
    size_t getScale() const { return scale; }
    int64_t getDisplacement() const { return displacement; }

    // After jump table passes have run, either the jumpTable pointer will be
    // set, or this jump has another purpose (e.g. indirect tail recursion).
    bool isForJumpTable() const { return !jumpTables.empty(); }
    const std::vector<JumpTable *> getJumpTables() const { return jumpTables; }
    void addJumpTable(JumpTable *jumpTable) { jumpTables.push_back(jumpTable); }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class IndirectCallInstruction : public IsolatedInstruction {
private:
    Register reg;
    bool memory;
    Register index; // only relevant if memory
    size_t scale;   // only relevant if memory
    int64_t displacement;   // only relevant if memory
public:
    IndirectCallInstruction(const Assembly &assembly, Register reg)
        : IsolatedInstruction(assembly), reg(reg), memory(false),
        index(INVALID_REGISTER), scale(1), displacement(0) {}

    IndirectCallInstruction(const Assembly &assembly, Register reg,
        Register index, size_t scale, int64_t displacement)
        : IsolatedInstruction(assembly), reg(reg), memory(true),
        index(index), scale(scale), displacement(displacement) {}

    Register getRegister() const { return reg; }
    bool hasMemoryOperand() const { return memory; }
    Register getIndexRegister() const { return index; }
    size_t getScale() const { return scale; }
    int64_t getDisplacement() const { return displacement; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

// brk and hlt
class BreakInstruction : public IsolatedInstruction {
public:
    using IsolatedInstruction::IsolatedInstruction;

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

#endif
