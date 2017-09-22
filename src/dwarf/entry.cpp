#include <cassert>
#include "entry.h"
#include "defines.h"

DwarfCIE::Augmentation::Augmentation() {
    this->personalityEncoding = 0;
    this->personalityEncodingRoutine = 0;
    this->codeEnc = 0;
    this->lsdaEnc = DW_EH_PE_omit;
    this->isSignal = false;
}

DwarfCIE::DwarfCIE(address_t startAddress, uint64_t length, uint64_t index)
    : DwarfEntry(startAddress, length), index(index) {

    this->cieId = 0;
    this->codeAlignFactor = 0;
    this->dataAlignFactor = 0;
    this->retAddressReg = 0;
}

DwarfFDE::DwarfFDE(address_t startAddress, uint64_t length, uint64_t cieIndex)
    : DwarfEntry(startAddress, length), cieIndex(cieIndex), ciePointer(0),
    pcBegin(0), pcRange(0) {

}

void DwarfUnwindInfo::addCIE(DwarfCIE *cie) {
    cieList.push_back(cie);
    cieMap[cie->getStartAddress()] = cie->getIndex();
}

void DwarfUnwindInfo::addFDE(DwarfFDE *fde) {
    fdeList.push_back(fde);
}

bool DwarfUnwindInfo::findCIE(address_t address, uint64_t *index) {
    auto it = cieMap.find(address);
    if(it != cieMap.end()) {
        *index = (*it).second;
        return true;
    }
    return false;
}

DwarfCIE *DwarfUnwindInfo::getCIE(uint64_t cieIndex) {
    assert(cieIndex < cieList.size());
    return cieList[cieIndex];
}
