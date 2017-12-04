#ifndef EGALITO_INSTR_CONCRETE_H
#define EGALITO_INSTR_CONCRETE_H

#include "semantic.h"
#include "register.h"

class IsolatedInstruction : public SemanticImpl {
public:
    virtual Link *getLink() const { return nullptr; }
    virtual void setLink(Link *link)
        { throw "Can't call setLink() on any IsolatedInstruction"; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class LiteralInstruction : public SemanticImpl {
public:
    // Cannot disassemble a LiteralInstruction.
    virtual AssemblyPtr getAssembly() { return AssemblyPtr(); }
    virtual void setAssembly(AssemblyPtr assembly)
        { throw "Can't call setAssembly() on LiteralInstruction"; }

    virtual Link *getLink() const { return nullptr; }
    virtual void setLink(Link *link)
        { throw "Can't call setLink() on any LiteralInstruction"; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class LinkedInstruction;
class ControlFlowInstruction;
class StackFrameInstruction;
class LinkedLiteralInstruction;

#include "linked-x86_64.h"
#include "linked-aarch64.h"
#include "linked-arm.h"

class ReturnInstruction : public IsolatedInstruction {
public:
    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class JumpTable;
class IndirectJumpInstruction : public IsolatedInstruction {
private:
    Register reg;
    std::string mnemonic;
    std::vector<JumpTable *> jumpTables;
public:
    IndirectJumpInstruction(Register reg, const std::string &mnemonic)
        : reg(reg), mnemonic(mnemonic) {}

    std::string getMnemonic() const { return mnemonic; }
    register_t getRegister() const { return reg; }

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
public:
    IndirectCallInstruction(Register reg) : reg(reg) {}

    register_t getRegister() const { return reg; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

// brk and hlt
class BreakInstruction : public IsolatedInstruction {
public:
    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

#endif
