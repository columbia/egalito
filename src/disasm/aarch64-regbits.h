#ifndef EGALITO_AARCH64_REGBITS_H
#define EGALITO_AARCH64_REGBITS_H

#include <vector>
#include <utility>
#include "instr/register.h"

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
class AARCH64RegBits {
private:
    uint32_t bin;
    const uint32_t regMask;
    bool cached;

    typedef std::vector<unsigned int> RegPositions;
    typedef std::pair<RegPositions, RegPositions> RegPositionsList;
    RegPositionsList list;

public:
    AARCH64RegBits() : regMask(0x1F), cached(false) {}
    void decode(const char *bytes);
    void encode(char *bytes);
    bool isReading(PhysicalRegister<AARCH64GPRegister> &reg);
    bool isWriting(PhysicalRegister<AARCH64GPRegister> &reg);
    void replaceRegister(PhysicalRegister<AARCH64GPRegister>& oldReg,
                         PhysicalRegister<AARCH64GPRegister>& newReg);

private:
    RegPositionsList getRegPositionList();
    void makeDPImm_RegPositionList();
    void makeBranch_RegPositionList();
    void makeLDST_RegPositionList();
    void makeDPIReg_RegPositionList();
};
#endif

#endif
