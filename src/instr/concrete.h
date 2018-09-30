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
    const std::string &getData() { return getStorage()->getData(); }

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
    virtual bool isControlFlow() const { return true; }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class IndirectControlFlowInstructionBase : public IsolatedInstruction {
private:
    Register reg;
    bool memory;
    Register index; // only relevant if memory
    size_t scale;   // only relevant if memory
    int64_t displacement;   // only relevant if memory
public:
    IndirectControlFlowInstructionBase(Register reg)
        : reg(reg), memory(false),
        index(INVALID_REGISTER), scale(1), displacement(0) {}

    IndirectControlFlowInstructionBase(Register reg,
        Register index, size_t scale, int64_t displacement)
        : reg(reg), memory(true),
        index(index), scale(scale), displacement(displacement) {}

    Register getRegister() const { return reg; }
    bool hasMemoryOperand() const { return memory; }
    Register getIndexRegister() const { return index; }
    size_t getScale() const { return scale; }
    int64_t getDisplacement() const { return displacement; }

    virtual bool isControlFlow() const { return true; }
};

class JumpTable;
class IndirectJumpInstruction : public IndirectControlFlowInstructionBase {
private:
    std::string mnemonic;
    std::vector<JumpTable *> jumpTables;
public:
    IndirectJumpInstruction(Register reg, const std::string &mnemonic)
        : IndirectControlFlowInstructionBase(reg), mnemonic(mnemonic) {}

    IndirectJumpInstruction(Register reg, const std::string &mnemonic,
        Register index, size_t scale, int64_t displacement)
        : IndirectControlFlowInstructionBase(reg, index, scale, displacement),
        mnemonic(mnemonic) {}

    std::string getMnemonic() const { return mnemonic; }

    // After jump table passes have run, either the jumpTable pointer will be
    // set, or this jump has another purpose (e.g. indirect tail recursion).
    bool isForJumpTable() const { return !jumpTables.empty(); }
    const std::vector<JumpTable *> getJumpTables() const { return jumpTables; }
    void addJumpTable(JumpTable *jumpTable) { jumpTables.push_back(jumpTable); }

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

class IndirectCallInstruction : public IndirectControlFlowInstructionBase {
public:
    using IndirectControlFlowInstructionBase::IndirectControlFlowInstructionBase;

    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

// brk and hlt
class BreakInstruction : public IsolatedInstruction {
public:
    virtual void accept(InstructionVisitor *visitor) { visitor->visit(this); }
};

#endif
