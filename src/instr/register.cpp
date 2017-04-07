#include "register.h"

#ifdef ARCH_AARCH64
int AARCH64GPRegister::convertToPhysical(int id) {
    static const int mappings[][3] = {
        {ARM64_REG_W0,  ARM64_REG_X0,  R0},
        {ARM64_REG_W1,  ARM64_REG_X1,  R1},
        {ARM64_REG_W2,  ARM64_REG_X2,  R2},
        {ARM64_REG_W3,  ARM64_REG_X3,  R3},
        {ARM64_REG_W4,  ARM64_REG_X4,  R4},
        {ARM64_REG_W5,  ARM64_REG_X5,  R5},
        {ARM64_REG_W6,  ARM64_REG_X6,  R6},
        {ARM64_REG_W7,  ARM64_REG_X7,  R7},
        {ARM64_REG_W8,  ARM64_REG_X8,  R8},
        {ARM64_REG_W9,  ARM64_REG_X9,  R9},
        {ARM64_REG_W10, ARM64_REG_X10, R10},
        {ARM64_REG_W11, ARM64_REG_X11, R11},
        {ARM64_REG_W12, ARM64_REG_X12, R12},
        {ARM64_REG_W13, ARM64_REG_X13, R13},
        {ARM64_REG_W14, ARM64_REG_X14, R14},
        {ARM64_REG_W15, ARM64_REG_X15, R15},
        {ARM64_REG_W16, ARM64_REG_X16, R16},
        {ARM64_REG_W17, ARM64_REG_X17, R17},
        {ARM64_REG_W18, ARM64_REG_X18, R18},
        {ARM64_REG_W19, ARM64_REG_X19, R19},
        {ARM64_REG_W20, ARM64_REG_X20, R20},
        {ARM64_REG_W21, ARM64_REG_X21, R21},
        {ARM64_REG_W22, ARM64_REG_X22, R22},
        {ARM64_REG_W23, ARM64_REG_X23, R23},
        {ARM64_REG_W24, ARM64_REG_X24, R24},
        {ARM64_REG_W25, ARM64_REG_X25, R25},
        {ARM64_REG_W26, ARM64_REG_X26, R26},
        {ARM64_REG_W27, ARM64_REG_X27, R27},
        {ARM64_REG_W28, ARM64_REG_X28, R28},
        {ARM64_REG_W29, ARM64_REG_X29, R29},
        {ARM64_REG_W30, ARM64_REG_X30, R30},
        {ARM64_REG_WSP, ARM64_REG_SP,  R31},
        {ARM64_REG_WZR, ARM64_REG_XZR, R31},
    };

    unsigned int guess = id - ARM64_REG_W0;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][0] == id) {
            return mappings[guess][2];
        }
    }
    guess = id - ARM64_REG_X0;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][1] == id) {
            return mappings[guess][2];
        }
    }

    for(size_t i = 0; i < sizeof(mappings)/sizeof(*mappings); i ++) {
        for(size_t j = 0; j < sizeof(*mappings)/sizeof(**mappings); j ++) {
            if(mappings[i][j] == id) {
                return mappings[i][2];
            }
        }
    }

    return AARCH64GPRegister::INVALID;
}
#endif
