#ifndef EGALITO_AARCH64_REGBITS_H
#define EGALITO_AARCH64_REGBITS_H

#include <vector>
#include <utility>
#include "register.h"

#ifdef ARCH_AARCH64
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
    virtual void decode(const char *bytes);
    virtual void encode(char *bytes);
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
#endif

