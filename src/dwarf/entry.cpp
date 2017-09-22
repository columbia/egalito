#include "entry.h"

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
}

DwarfFDE::DwarfFDE(address_t startAddress, uint64_t length, uint64_t cieIndex)
    : DwarfEntry(startAddress, length), cieIndex(cieIndex), ciePointer(0),
    pcBegin(0), pcRange(0) {

}
