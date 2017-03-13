#include <vector>
#include <utility>
#include "chunkpass.h"
#include "stackextend.h"
#include "chunk/register.h"

#ifdef ARCH_AARCH64
template<typename RegisterType>
class RegisterUsage {
public:
    virtual std::set<Block *> getSingleBlockList();
    virtual std::set<Block *> getRootBlockList();
    virtual std::set<Block *> getLeafBlockList();
    virtual std::vector<Instruction *> getInstructionList(Block *block);

    // in the extreme case, this has to be considered per instruction.
    virtual typename RegisterType::ID getDualableID(Block *block);
};

template <typename RegisterType>
class RegReplacePass : public StackExtendPass {
public:
    RegReplacePass(typename RegisterType::ID id, size_t saveSize)
        : StackExtendPass(saveSize) {}
    virtual void useStack(Function *function, FrameType *frame);

private:
    virtual void replaceRoot(Block *block, FrameType *frame,
                     RegisterUsage<RegisterType> *regUsage) {}
    virtual void replaceLeaf(Block *block, FrameType *frame,
                     RegisterUsage<RegisterType> *regUsage) {}
    virtual void replaceSingle(Block *block, FrameType *frame,
                       RegisterUsage<RegisterType> *regUsage) {}
};

template <typename RegisterType>
class InstructionCoder {
public:
    virtual void decode(uint8_t *bytes, size_t size);
    virtual void encode(uint8_t *bytes, size_t size);
    virtual bool isReading(PhysicalRegister<RegisterType> &reg);
    virtual bool isWriting(PhysicalRegister<RegisterType> &reg);
    virtual void replaceRegister(PhysicalRegister<RegisterType>& oldReg,
                                 PhysicalRegister<RegisterType>& newReg);
};


class AARCH64RegisterUsage : public RegisterUsage<AARCH64GPRegister> {
private:
    Function *function;
    PhysicalRegister<AARCH64GPRegister> regX;

    std::map<Block *, std::vector<Instruction *>> UsageList;
    std::set<AARCH64GPRegister> incompatibleList;
    std::set<Block *> singleBlockList;
    std::set<Block *> rootBlockList;
    std::set<Block *> leafBlockList;

    bool cached;

public:
    AARCH64RegisterUsage(Function *function, AARCH64GPRegister::ID id)
        : function(function), regX(id, true), cached(false) {}

    virtual std::set<Block *> getSingleBlockList();
    virtual std::set<Block *> getRootBlockList();
    virtual std::set<Block *> getLeafBlockList();
    virtual std::vector<Instruction *> getInstructionList(Block *block) {
        return UsageList[block]; }

    virtual typename AARCH64GPRegister::ID getDualableID(Block *block);

private:
    std::map<Block *, std::vector<Instruction *>> getUsageList() {
        return UsageList; }
    void categorizeBlocks();
    void makeUsageList();
    bool dualSafe(AARCH64GPRegister::ID id);
};

class AARCH64RegReplacePass : public RegReplacePass<AARCH64GPRegister> {
private:
    PhysicalRegister<AARCH64GPRegister> regX;

public:
    AARCH64RegReplacePass(AARCH64GPRegister::ID id, size_t saveSize)
        : RegReplacePass<AARCH64GPRegister>(id, saveSize),
          regX(PhysicalRegister<AARCH64GPRegister>(id, true)) {};

    virtual void useStack(Function *function, FrameType *frame);
    virtual void replaceRoot(Block *block, FrameType *frame,
                             RegisterUsage<AARCH64GPRegister> *regUsage);
    virtual void replaceLeaf(Block *block, FrameType *frame,
                             RegisterUsage<AARCH64GPRegister> *regUsage);
    virtual void replaceSingle(Block *block, FrameType *frame,
                               RegisterUsage<AARCH64GPRegister> *regUsage);

private:
    void replace(Block *block, FrameType *frame,
                 RegisterUsage<AARCH64GPRegister> *regUsage,
                 bool skipHead, bool skipTail);
};

class AARCH64InstructionCoder : public InstructionCoder<AARCH64GPRegister> {
private:
    uint32_t bin;
    const uint32_t regMask;
    bool cached;

    typedef std::vector<unsigned int> RegPositions;
    typedef std::pair<RegPositions, RegPositions> RegPositionsList;
    RegPositionsList list;

public:
    AARCH64InstructionCoder() : regMask(0x1F), cached(false) {}
    virtual void decode(uint8_t *bytes, size_t size);
    virtual void encode(uint8_t *bytes, size_t size);
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

