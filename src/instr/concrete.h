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
};

class IndirectJumpInstruction : public IsolatedInstruction {
private:
    Register reg;
    std::string mnemonic;
public:
    IndirectJumpInstruction(const Assembly &assembly, Register reg,
        const std::string &mnemonic)
        : IsolatedInstruction(assembly), reg(reg),
        mnemonic(mnemonic) {}

    std::string getMnemonic() const { return mnemonic; }
    register_t getRegister() const { return reg; }
};

#endif
