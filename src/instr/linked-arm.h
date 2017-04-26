#ifndef EGALITO_INSTR_LINKED_ARM_H
#define EGALITO_INSTR_LINKED_ARM_H

#include "semantic.h"
#include "isolated.h"
#include "chunk/chunkfwd.h"

// Defines LinkedInstruction and ControlFlowInstruction for arm.

#if defined(ARCH_ARM)
class LinkedInstruction : public LinkDecorator<DisassembledInstruction> {
public:
    enum Mode {
        ARM_IM_ADDIMM,
        ARM_IM_LDR,
        ARM_IM_BL,
        ARM_IM_B,
        ARM_IM_BLX,
        ARM_IM_BX,
        ARM_IM_BXJ,
        ARM_IM_BCOND,
        ARM_IM_CBZ,
        ARM_IM_CBNZ,
        ARM_IM_MAX
    };

private:
    struct ARM_modeInfo_t {
        uint32_t fixedMask;
        uint32_t (*makeImm)(address_t, address_t);
        int immediateIndex;
    };

    const static ARM_modeInfo_t ARM_ImInfo[ARM_IM_MAX];

    Instruction *source;
    const ARM_modeInfo_t *modeInfo;

public:
    LinkedInstruction(Instruction *source,
                      const Assembly &assembly);

    virtual void writeTo(char *target);
    virtual void writeTo(std::string &target);
    virtual std::string getData();

    void regenerateAssembly();

    static LinkedInstruction *makeLinked(Module *module,
        Instruction *instruction, Assembly *assembly);

    Instruction *getSource() const { return source; }
    std::string getMnemonic() { return getAssembly()->getMnemonic(); }

    const ARM_modeInfo_t *getModeInfo() const { return modeInfo; }
    uint32_t getOriginalOffset() const;

    uint32_t rebuild();

private:
    static Mode getMode(const Assembly &assembly);
    static address_t makeTargetAddress(Instruction *instruction,
        Assembly *assembly, int regIndex);
};

class ControlFlowInstruction : public LinkedInstruction {
public:
    using LinkedInstruction::LinkedInstruction;
};
#endif

#endif
