#ifndef EGALITO_DWARF_ENTRY_H
#define EGALITO_DWARF_ENTRY_H

class Entry {
protected:
    address_t startAddress;
    uint64_t length;        // size of CIE structure, excluding length field
    uint64_t entryLength;   // size of CIE/FDE, including the length field
public:
    //void parseInstructions(Cursor start, Cursor end, CommonInformationEntry* cie, state_t *state, uint64_t cfaIp, state_t** rememberedState);
};

class CommonInformationEntry : private Entry {
public:
    class Augmentation {
    private:
        uint64_t augmentationSectionLength;
        uint8_t personalityEncoding;
        uint64_t personalityEncodingRoutine;
        uint8_t codeEnc;
        uint8_t lsdaEnc;
        bool isSignal;
    public:
        uint64_t getAugmentationSectionLength() const
            { return augmentationSectionLength; }
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
    uint8_t  version;
    uint8_t *cieAugmentationString;
    uint64_t codeAlignFactor;
    int64_t  dataAlignFactor;
    uint64_t retAddressReg;
    bool augmentationSectionExistsInFDEs;

    Augmentation *augmentation;
private:
    state_t state;
public:
    void parseCIE(Cursor start, address_t ehSectionStartAddress, state_t** rememberedState);
    CommonInformationEntry(Cursor start, uint64_t entryLength, uint64_t length,
        uint64_t index, address_t ehSectionStartAddress, state_t** rememberedState);

    address_t getCieStartAddress() const { return startAddress; }
    uint64_t getIndex() const { return index; }
    uint64_t getCieLength() const { return entryLength; }
    uint64_t getLength() const { return length; }
    uint32_t getCieId() const { return cieId; }
    uint8_t getVersion() const { return version; }
    uint8_t *getCieAugmentationString() const { return cieAugmentationString; }
    uint64_t getCodeAlignFactor() const { return codeAlignFactor; }
    int64_t getDataAlignFactor() const { return dataAlignFactor; }
    uint64_t getRetAddressReg() const { return retAddressReg; }

    bool doFDEsHaveAugmentationSection() const
        { return augmentationSectionExistsInFDEs; }
};

class FrameDescriptorEntry : private Entry {
private:
    uint64_t cieIndex;
    uint32_t ciePointer;
    int64_t pcBegin;
    uint64_t pcRange;
    uint64_t augmentationSectionLength;
    uint64_t lsdaPointer;
public:
    FrameDescriptorEntry(Cursor start, uint64_t entryLength, uint64_t length,
        uint32_t ciePointer, CommonInformationEntry *cie, uint64_t cieIndex,
        address_t ehSectionStartAddress, address_t ehSectionShAddr,
        state_t **rememberedState);
    void parseFDE(Cursor start, CommonInformationEntry* cie,
        address_t ehSectionStartAddress, address_t ehSectionShAddr,
        state_t **rememberedState);

    uint64_t getLsdaPointer() const { return lsdaPointer; }
    uint64_t getAugmentationSectionLength() const
        { return augmentationSectionLength; }
    uint64_t getPcRange() const { return pcRange; }
    int64_t getPcBegin() const { return pcBegin; }
    uint32_t getCiePointer() const { return ciePointer; }
    uint64_t getLength() const { return length; }
    uint64_t getFdeLength() const { return entryLength; }
    uint64_t getCieIndex() const { return cieIndex; }
    address_t getFdeStartAddress() const { return startAddress; }
};

#endif
