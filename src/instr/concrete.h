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
    JumpTable *jumpTable;
public:
    IndirectJumpInstruction(const Assembly &assembly, Register reg,
        const std::string &mnemonic)
        : IsolatedInstruction(assembly), reg(reg),
        mnemonic(mnemonic), jumpTable(nullptr) {}

    std::string getMnemonic() const { return mnemonic; }
    register_t getRegister() const { return reg; }

    // After jump table passes have run, either the jumpTable pointer will be
    // set, or this jump has another purpose (e.g. indirect tail recursion).
    bool isForJumpTable() const { return jumpTable != nullptr; }
    JumpTable *getJumpTable() const { return jumpTable; }
    void setJumpTable(JumpTable *jumpTable) { this->jumpTable = jumpTable; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class IndirectCallInstruction : public IsolatedInstruction {
private:
    Register reg;
public:
    IndirectCallInstruction(const Assembly &assembly, Register reg)
        : IsolatedInstruction(assembly), reg(reg) {}

    register_t getRegister() const { return reg; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

// brk and hlt
class BreakInstruction : public IsolatedInstruction {
public:
    using IsolatedInstruction::IsolatedInstruction;

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

#endif
