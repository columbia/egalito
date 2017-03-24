#include <vector>
#include <utility>
#include "chunkpass.h"
#include "stackextend.h"
#include "chunk/register.h"

#ifdef ARCH_AARCH64
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
        : StackExtendPass(saveSize),
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

class AARCH64InstructionRegCoder {
private:
    uint32_t bin;
    const uint32_t regMask;
    bool cached;

    typedef std::vector<unsigned int> RegPositions;
    typedef std::pair<RegPositions, RegPositions> RegPositionsList;
    RegPositionsList list;

public:
    AARCH64InstructionRegCoder() : regMask(0x1F), cached(false) {}
    virtual void decode(const char *bytes, size_t size);
    virtual void encode(char *bytes, size_t size);
    virtual bool isReading(PhysicalRegister<AARCH64GPRegister> &reg);
    virtual bool isWriting(PhysicalRegister<AARCH64GPRegister> &reg);
    virtual void replaceRegister(PhysicalRegister<AARCH64GPRegister>& oldReg,
                                 PhysicalRegister<AARCH64GPRegister>& newReg);

private:
    RegPositionsList getRegPositionList();
    void makeDPImm_RegPositionList();
    void makeBranch_RegPositionList();
    void makeLDST_RegPositionList();
    void makeDPIReg_RegPositionList();
};
#endif

