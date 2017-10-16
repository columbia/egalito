#ifndef EGALITO_PASS_REGREPLACE_H
#define EGALITO_PASS_REGREPLACE_H

#include <vector>
#include "stackextend.h"
#include "instr/register.h"

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
class AARCH64RegisterUsageX;

class AARCH64RegReplacePass : public StackExtendPass {
private:
    PhysicalRegister<AARCH64GPRegister> regX;

public:
    AARCH64RegReplacePass(AARCH64GPRegister::ID id, size_t saveSize)
        : StackExtendPass(saveSize),
          regX(PhysicalRegister<AARCH64GPRegister>(id, true)) {};

    virtual void replacePerFunction(Function *function,
                                    FrameType *frame,
                                    AARCH64RegisterUsageX *regUsage,
                                    AARCH64GPRegister::ID dualID);
    virtual void replacePerInstruction(FrameType *frame,
                                       AARCH64RegisterUsageX *regUsage,
                                       AARCH64GPRegister::ID dualID);
private:
    virtual bool shouldApply(Function *function);
    virtual void useStack(Function *function, FrameType *frame);
    std::vector<Instruction *> getCallingInstructions(Function *function);
};

#endif

#endif
