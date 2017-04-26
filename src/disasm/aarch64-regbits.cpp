#include "disasm/aarch64-regbits.h"

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
void AARCH64RegBits::decode(const char *bytes) {
    bin = bytes[3] << 24 | bytes[2] << 16 | bytes[1] << 8 | bytes[0];
    cached = false;
}

void AARCH64RegBits::encode(char *bytes) {
    bytes[0] = bin >>  0 & 0xFF;
    bytes[1] = bin >>  8 & 0xFF;
    bytes[2] = bin >> 16 & 0xFF;
    bytes[3] = bin >> 24 & 0xFF;
}

bool AARCH64RegBits::isReading(
    PhysicalRegister<AARCH64GPRegister>& reg) {

    auto list = getRegPositionList();
    for(auto rpos : list.first) {
        uint32_t rr = bin >> rpos & regMask;
        if(rr == reg.encoding()) {
            return true;
        }
    }
    return false;
}

bool AARCH64RegBits::isWriting(
    PhysicalRegister<AARCH64GPRegister>& reg) {

    auto list = getRegPositionList();
    for(auto wpos : list.second) {
        uint32_t wr = bin >> wpos & regMask;
        if(wr == reg.encoding()) {
            return true;
        }
    }
    return false;
}


void AARCH64RegBits::replaceRegister(
    PhysicalRegister<AARCH64GPRegister>& oldReg,
    PhysicalRegister<AARCH64GPRegister>& newReg) {

    auto list = getRegPositionList();
    for(auto rpos : list.first) {
        auto rr = bin >> rpos & regMask;
        if(rr == oldReg.encoding()) {
            bin = (bin & ~(regMask << rpos)) | (newReg.encoding() << rpos);
        }
    }

    for(auto wpos : list.second) {
        auto wr = bin >> wpos & regMask;
        if(wr == oldReg.encoding()) {
            bin = (bin & ~(regMask << wpos)) | (newReg.encoding() << wpos);
        }
    }
    cached = false;
}

AARCH64RegBits::RegPositionsList AARCH64RegBits::getRegPositionList() {
    if(!cached) {
        //C4.1
        auto op0 = bin >> 25 & 0xF;
        if((op0 & 0b1110) == 0b1000) makeDPImm_RegPositionList();
        else if((op0 & 0b1010) == 0b1010) makeBranch_RegPositionList();
        else if((op0 & 0b0101) == 0b0100) makeLDST_RegPositionList();
        else if((op0 & 0b0111) == 0b0101) makeDPIReg_RegPositionList();
#if 1
        else {
            throw "unhandled instruction category";
        }
#endif
        cached = true;
    }

    return list;
}

void AARCH64RegBits::makeDPImm_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    if(1
        || (bin & 0x1F000000) == 0x11000000     //C4.2.1 Add/subtract (immediate)
        || (bin & 0x1F800000) == 0x13000000     //C4.2.2 Bitfield
        || (bin & 0x1F800000) == 0x12000000     //C4.2.4 Logical (immediate)
      ) {
        source.push_back(5);
        destination.push_back(0);
    }
    else if((bin & 0x1F800000) == 0x13800000) { //C4.2.3 Extract
        source.push_back(5);
        source.push_back(16);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x1F800000) == 0x12800000     //C4.2.5 Move wide (immediate)
        || (bin & 0x1F000000) == 0x10000000     //C4.2.6 PC-rel. addressing
           ) {
        destination.push_back(0);
    }

    list = RegPositionsList(source, destination);
}

void AARCH64RegBits::makeBranch_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    if(1
        || (bin & 0xFE000000) == 0x34000000     //C4.3.1 Compare & branch (imm)
        || (bin & 0x7E000000) == 0x36000000     //C4.3.5 Test & branch (immediate)
      ) {
        source.push_back(0);
    }
    else if((bin & 0xFFC00000) == 0xD5000000    //C4.3.4 System
           ) {
        auto L = bin >> 21 & 0x1;
        auto op0 = bin >> 19 & 0x3;
        if(L == 0) {
            if(op0 == 0x1 || ((op0 & 0x3) == 0x3)) {  //SYS, MSR (register)
                source.push_back(0);
            }
        }
        else if(L == 1) { //SYSL, MRS
            destination.push_back(0);
        }
    }
    else if((bin & 0xFE000000) == 0xD6000000) { //C4.3.7 Uncoditional branch (reg)
        source.push_back(5);
    }

    //No register use
    //C4.3.2 Conditional branch (immediate)
    //C4.3.3 Exception generation
    //C4.3.6 Uncoditional branch (immediate)

    list = RegPositionsList(source, destination);
}

void AARCH64RegBits::makeLDST_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    auto op1 = bin >> 28 & 0x3;
    if(op1 == 0) {
        throw "unhandled SIMD and LD exclusive instructions";
    }

    if((bin & 0x3B000000)== 0x18000000          //C4.4.5 Load (literal)
      ) {
       destination.push_back(0);
    }
    else if(1
        || (bin & 0x3B200C00) == 0x38000400     //C4.4.8 LD/ST (imm post)
        || (bin & 0x3B200C00) == 0x38000C00     //C4.4.9 LD/ST (imm pre)
        || (bin & 0x3B200C00) == 0x38000800     //C4.4.11 LD/ST (unprivileged)
        || (bin & 0x3B200C00) == 0x38000000     //C4.4.12 LD/ST (unscaled imm)
        || (bin & 0x3B000C00) == 0x39000000     //C4.4.13 LD/ST (unsigned imm)
           ){
        auto writeback = (bin >> 10 & 0x1);
        switch((bin & 0x04000000 >> (26 - 2)) | (bin & 0x00C00000 >> 22)) {
        case 1: case 2: case 3: case 5: case 7: //LD
            source.push_back(5);
            destination.push_back(0);
            if(writeback) {
                destination.push_back(5);
            }
            break;
        case 0: case 4: case 6: //ST
            source.push_back(0);
            source.push_back(5);
            if(writeback) {
                destination.push_back(5);
            }
            break;
        default:
            break;
        }
    }
    else if((bin & 0x3B200C00) == 0x38200800) { //C4.4.10 LD/ST (register)
        switch((bin & 0x04000000 >> (26 - 2)) | (bin & 0x00C00000 >> 22)) {
        case 1: case 2: case 3: case 5: case 7: //LD
            source.push_back(5);
            source.push_back(16);
            destination.push_back(0);
        case 0: case 4: case 6: //ST
            source.push_back(0);
            source.push_back(5);
            source.push_back(16);
            break;
        default:
            break;
        }
    }
    else if(1
        || (bin & 0x3BC00000) == 0x28000000     //C4.4.7 LD/ST no-a pair (offset)
        || (bin & 0x3B800000) == 0x29000000     //C4.4.14 LD/ST pair (offset)
        || (bin & 0x3B800000) == 0x28800000     //C4.4.15 LD/ST pair (post)
        || (bin & 0x3B800000) == 0x29800000     //C4.4.15 LD/ST pair (pre)
           ) {
        auto writeback = (bin >> 23 & 0x1);
        auto L = bin >> 22 & 0x1;
        if(L) {
            source.push_back(5);
            destination.push_back(0);
            destination.push_back(10);
            if(writeback) {
                destination.push_back(5);
            }
        }
        else {
            source.push_back(0);
            source.push_back(5);
            source.push_back(10);
            if(writeback) {
                destination.push_back(5);
            }
        }
    }

    list = RegPositionsList(source, destination);
}

void AARCH64RegBits::makeDPIReg_RegPositionList() {
    RegPositions source;
    RegPositions destination;

    if(1
        || (bin & 0x1F200000) == 0x0B200000     //C4.5.1 Add/subtract (extended)
        || (bin & 0x1F200000) == 0x0B000000     //C4.5.2 Add/subtract (shifted)
        || (bin & 0x1FE00000) == 0x1A000000     //C4.5.3 Add/subtract (w/ carry)
        || (bin & 0x1FE00800) == 0x1A400000     //C4.5.5 Conditional compare (reg)
        || (bin & 0x3FE00000) == 0x1AC00000     //C4.5.8 Data-processing (2 src)
        || (bin & 0x1F000000) == 0x0A000000     //C4.5.10 Logical (shifted)
      ) {
        source.push_back(5);
        source.push_back(16);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x1FE00800) == 0x1A400800     //C4.5.4 Conditional compare (imm)
      ) {
        source.push_back(5);
    }
    else if(1
        || (bin & 0x1FE00000) == 0x1A800000     //C4.5.6 Conditional select
      ) {
        source.push_back(5);
        source.push_back(16);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x3FE00000) == 0x3AC00000     //C4.5.7 Data-processing (1 src)
      ) {
        source.push_back(5);
        destination.push_back(0);
    }
    else if(1
        || (bin & 0x1F000000) == 0x1A000000     //C4.5.9 Data-processing (3 src)
      ) {
        source.push_back(5);
        source.push_back(10);
        source.push_back(16);
        destination.push_back(0);
    }

    list = RegPositionsList(source, destination);
}
#endif
