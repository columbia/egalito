#ifndef EGALITO_DWARF_ENTRY_H
#define EGALITO_DWARF_ENTRY_H

#include <vector>
#include <unordered_map>
#include "types.h"

class DwarfState;

// Base class for Dwarf CIE/FDEs
class DwarfEntry {
private:
    address_t startAddress;
    uint64_t length;        // size of CIE structure, excluding length field
    DwarfState *state;
public:
    DwarfEntry(address_t startAddress, uint64_t length)
        : startAddress(startAddress), length(length), state(nullptr) {}

    void setState(DwarfState *state) { this->state = state; }

    address_t getStartAddress() const { return startAddress; }
    uint64_t getLength() const { return length; }
    DwarfState *getState() const { return state; }
};

// Dwarf Common Information Entry (CIE)
class DwarfCIE : public DwarfEntry {
public:
    class Augmentation {
    private:
        uint8_t personalityEncoding;
        uint64_t personalityEncodingRoutine;
        uint8_t codeEnc;
        uint8_t lsdaEnc;
        bool isSignal;
    public:
        Augmentation();

        void setPersonalityEncoding(uint8_t personalityEncoding)
            { this->personalityEncoding = personalityEncoding; }
        void setPersonalityEncodingRoutine(uint64_t personalityEncodingRoutine)
            { this->personalityEncodingRoutine = personalityEncodingRoutine; }
        void setCodeEnc(uint8_t codeEnc) { this->codeEnc = codeEnc; }
        void setLsdaEnc(uint8_t lsdaEnc) { this->lsdaEnc = lsdaEnc; }
        void setIsSignal(bool isSignal) { this->isSignal = isSignal; }

        uint8_t getPersonalityEncoding() const { return personalityEncoding; }
        uint64_t getPersonalityEncodingRoutine() const
            { return personalityEncodingRoutine; }
        uint8_t getCodeEnc() const { return codeEnc; }
        uint8_t getLsdaEnc() const { return lsdaEnc; }
        bool getIsSignal() const { return isSignal; }
    };
private:
    uint64_t index;
    uint32_t cieId;
    uint64_t codeAlignFactor;
    int64_t dataAlignFactor;
    uint64_t retAddressReg;

    Augmentation *augmentation;
private:
    //state_t state;
public:
    DwarfCIE(address_t startAddress, uint64_t length, uint64_t index);

    void setAugmentation(Augmentation *augmentation)
        { this->augmentation = augmentation; }
    Augmentation *getAugmentation() const { return augmentation; }

    void setCodeAlignFactor(uint64_t codeAlignFactor)
        { this->codeAlignFactor = codeAlignFactor; }
    void setDataAlignFactor(uint64_t dataAlignFactor)
        { this->dataAlignFactor = dataAlignFactor; }
    void setRetAddressReg(uint64_t reg) { retAddressReg = reg; }

    uint64_t getIndex() const { return index; }
    uint32_t getCieId() const { return cieId; }
    uint64_t getCodeAlignFactor() const { return codeAlignFactor; }
    int64_t getDataAlignFactor() const { return dataAlignFactor; }
    uint64_t getRetAddressReg() const { return retAddressReg; }
};

// Dwarf Frame Descriptor Entry (FDE)
class DwarfFDE : public DwarfEntry {
public:
    class Augmentation {
    private:
        uint64_t lsdaPointer;
    public:
        Augmentation(uint64_t lsdaPointer) : lsdaPointer(lsdaPointer) {}
        uint64_t getLsdaPointer() const { return lsdaPointer; }
    };
private:
    uint64_t cieIndex;
    uint32_t ciePointer;
    int64_t pcBegin;
    uint64_t pcRange;

    Augmentation *augmentation;
public:
    DwarfFDE(address_t startAddress, uint64_t length, uint64_t cieIndex);

    void setAugmentation(Augmentation *augmentation)
        { this->augmentation = augmentation; }
    Augmentation *getAugmentation() const { return augmentation; }

    void setCiePointer(uint32_t ciePointer) { this->ciePointer = ciePointer; }
    void setPcBegin(int64_t pcBegin) { this->pcBegin = pcBegin; }
    void setPcRange(int64_t pcRange) { this->pcRange = pcRange; }

    uint64_t getCieIndex() const { return cieIndex; }
    uint32_t getCiePointer() const { return ciePointer; }
    uint64_t getPcRange() const { return pcRange; }
    int64_t getPcBegin() const { return pcBegin; }
};

class DwarfUnwindInfo {
private:
    std::vector<DwarfCIE *> cieList;
    std::vector<DwarfFDE *> fdeList;
    std::unordered_map<address_t, uint64_t> cieMap;
public:
    void addCIE(DwarfCIE *cie);
    void addFDE(DwarfFDE *fde);

    uint64_t getCIECount() const { return cieList.size(); }
    bool findCIE(address_t address, uint64_t *index);
    DwarfCIE *getCIE(size_t cieIndex);
};

#endif
