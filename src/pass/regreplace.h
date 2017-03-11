#include <bitset>
#include "chunkpass.h"
#include "stackextend.h"
#include "chunk/register.h"

class RegReplacePass : public StackExtendPass {
private:
    Register regX;
    size_t saveSize;

public:
    RegReplacePass(Register regX, size_t saveSize)
        : StackExtendPass(saveSize), regX(regX) {};
    virtual void useStack(Function *function, FrameType *frame);

private:
    void replaceRoot(Block *block, FrameType *frame, RegisterUsage *regUsage) {
        replace(block, frame, regUsage, true, false); }
    void replaceLeaf(Block *block, FrameType *frame, RegisterUsage *regUsage) {
        replace(block, frame, regUsage, false, true); }
    void replaceSingle(Block *block, FrameType *frame, RegisterUsage *regUsage) {
        replace(block, frame, regUsage, true, true); }
    void replace(Block *block, FrameType *frame, RegisterUsage *regUsage,
        bool skipHead, bool skipTail);
};

class InstructionCoder {
private:
    uint32_t bin;
    bool cached;
    typedef std::vector<unsigned int> RegPositions;
    typedef std::pair<RegPositions, RegPositions> RegPositionsList;
    RegPositionsList list;
    const uint32_t regMask;

public:
    InstructionCoder() : cached(false), regMask(0x1F) {}
    void decode(uint8_t *bytes, size_t size);
    void encode(uint8_t *bytes, size_t size);
    bool isReading(Register reg);
    bool isWriting(Register reg);
    void replaceRegister(Register oldName, Register newName);

private:
    RegPositionsList getRegPositionList();
    void makeDPImm_RegPositionList();
    void makeBranch_RegPositionList();
    void makeLDST_RegPositionList();
    void makeDPIReg_RegPositionList();
};

