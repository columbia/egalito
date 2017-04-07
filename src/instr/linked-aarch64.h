#ifndef EGALITO_INSTR_LINKED_AARCH64_H
#define EGALITO_INSTR_LINKED_AARCH64_H

#include "semantic.h"
#include "isolated.h"

// Defines LinkedInstruction and ControlFlowInstruction for aarch64.

#ifdef ARCH_AARCH64
class LinkedInstruction : public LinkDecorator<DisassembledInstruction> {
public:
    enum Mode {
        AARCH64_IM_ADRP = 0,
        AARCH64_IM_ADDIMM,
        AARCH64_IM_LDR,
        AARCH64_IM_BL,
        AARCH64_IM_B,
        AARCH64_IM_BCOND,
        AARCH64_IM_CBZ,
        AARCH64_IM_CBNZ,
        AARCH64_IM_TBZ,
        AARCH64_IM_TBNZ,
        AARCH64_IM_MAX
    };

private:
    struct AARCH64_modeInfo_t {
        uint32_t fixedMask;
        uint32_t (*makeImm)(address_t, address_t);
        int immediateIndex;
    };

    const static AARCH64_modeInfo_t AARCH64_ImInfo[AARCH64_IM_MAX];

    Instruction *source;
    const AARCH64_modeInfo_t *modeInfo;

public:
    LinkedInstruction(Instruction *source,
                      const Assembly &assembly);

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    void regenerateAssembly();
    virtual Assembly *getAssembly();

    Instruction *getSource() const { return source; }
    std::string getMnemonic() { return getAssembly()->getMnemonic(); }

    const AARCH64_modeInfo_t *getModeInfo() const { return modeInfo; }
    uint32_t getOriginalOffset() const;

    virtual uint32_t rebuild();

private:
    static Mode getMode(const Assembly &assembly);
};

class ControlFlowInstruction : public LinkedInstruction {
public:
    using LinkedInstruction::LinkedInstruction;
};

// This semantic is used for code pointers in .got section. An example case
// is in _start for PIE. This semantics adjust the offset to .got and
// another pass adjusts the actual data in .got.
// !!! please remove this
class PCRelativeInstruction : public LinkedInstruction {
public:
    using LinkedInstruction::LinkedInstruction;
};

// !!! please remove this
typedef LinkedInstruction PCRelativePageInstruction;
#endif

#endif
