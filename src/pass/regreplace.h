#ifndef EGALITO_PASS_REGREPLACE_H
#define EGALITO_PASS_REGREPLACE_H

#include <vector>
#include <utility>
#include "stackextend.h"
#include "instr/register.h"

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
class AARCH64RegisterUsage {
private:
    Function *function;
    PhysicalRegister<AARCH64GPRegister> regX;

    std::vector<Instruction *> xList;

public:
    AARCH64RegisterUsage(Function *function, AARCH64GPRegister::ID id);

    std::vector<Instruction *> getInstructionList() const { return xList; }
    std::vector<int> getAllUseCounts();
    std::vector<bool> getUnusableRegister();
};

class AARCH64RegReplacePass : public StackExtendPass {
private:
    PhysicalRegister<AARCH64GPRegister> regX;

public:
    AARCH64RegReplacePass(AARCH64GPRegister::ID id, size_t saveSize)
        : StackExtendPass(saveSize, false),
          regX(PhysicalRegister<AARCH64GPRegister>(id, true)) {};

    virtual void replacePerFunction(Function *function,
                                    FrameType *frame,
                                    AARCH64RegisterUsage *regUsage,
                                    AARCH64GPRegister::ID dualID);
    virtual void replacePerInstruction(FrameType *frame,
                                       AARCH64RegisterUsage *regUsage,
                                       AARCH64GPRegister::ID dualID);
private:
    virtual bool shouldApply(Function *function);
    virtual void useStack(Function *function, FrameType *frame);
    std::vector<Instruction *> getCallingInstructions(Function *function);
};

#endif

#endif
