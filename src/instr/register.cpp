#include "register.h"
#include "disasm/handle.h"

#ifdef ARCH_X86_64
const int X86Register::mappings[][5] = {
    {R0,  X86_REG_AL,   X86_REG_AX,   X86_REG_EAX,  X86_REG_RAX},
    {R1,  X86_REG_CL,   X86_REG_CX,   X86_REG_ECX,  X86_REG_RCX},
    {R2,  X86_REG_DL,   X86_REG_DX,   X86_REG_EDX,  X86_REG_RDX},
    {R3,  X86_REG_BL,   X86_REG_BX,   X86_REG_EBX,  X86_REG_RBX},
    {R4,  X86_REG_SPL,  X86_REG_SP,   X86_REG_ESP,  X86_REG_RSP},
    {R5,  X86_REG_BPL,  X86_REG_BP,   X86_REG_EBP,  X86_REG_RBP},
    {R6,  X86_REG_SIL,  X86_REG_SI,   X86_REG_ESI,  X86_REG_RSI},
    {R7,  X86_REG_DIL,  X86_REG_DI,   X86_REG_EDI,  X86_REG_RDI},
    {R8,  X86_REG_R8B,  X86_REG_R8W,  X86_REG_R8D,  X86_REG_R8},
    {R9,  X86_REG_R9B,  X86_REG_R9W,  X86_REG_R9D,  X86_REG_R9},
    {R10, X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10},
    {R11, X86_REG_R11B, X86_REG_R11W, X86_REG_R11D, X86_REG_R11},
    {R12, X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12},
    {R13, X86_REG_R13B, X86_REG_R13W, X86_REG_R13D, X86_REG_R13},
    {R14, X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14},
    {R15, X86_REG_R15B, X86_REG_R15W, X86_REG_R15D, X86_REG_R15},
};

const char *X86Register::getRepresentativeName(int reg) {
    static DisasmHandle handle;
    if(reg == X86Register::FLAGS) return "flags";
    return cs_reg_name(handle.raw(), mappings[reg][4]);
}

int X86Register::convertToPhysicalINT(int id) {
    unsigned int guess = id - X86_REG_AL;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][1] == id) {
            return mappings[guess][0];
        }
    }
    guess = id - X86_REG_AX;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][2] == id) {
            return mappings[guess][0];
        }
    }
    guess = id - X86_REG_EAX;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][2] == id) {
            return mappings[guess][0];
        }
    }
    guess = id - X86_REG_RAX;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][2] == id) {
            return mappings[guess][0];
        }
    }

    for(size_t i = 0; i < sizeof(mappings)/sizeof(*mappings); i ++) {
        for(size_t j = 1; j < sizeof(*mappings)/sizeof(**mappings); j ++) {
            if(mappings[i][j] == id) {
                return mappings[i][0];
            }
        }
    }

    switch(id) {
    case X86_REG_AH: return R0;
    case X86_REG_BH: return R3;
    case X86_REG_CH: return R1;
    case X86_REG_DH: return R2;
    }

    return X86Register::INVALID;
}

int X86Register::convertToPhysical(int id) {
    return convertToPhysicalINT(id);
}

size_t X86Register::getWidth(int pid, int id) {
    switch(id) {
    case X86_REG_AH: return 1;
    case X86_REG_BH: return 1;
    case X86_REG_CH: return 1;
    case X86_REG_DH: return 1;
    }

    size_t size = 1;
    for(size_t i = 1; i < sizeof(mappings)/sizeof(*mappings); i ++) {
        if(mappings[pid][i] == id) {
            size <<= i - 1;
            break;
        }
    }
    return size;
}
#endif

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
const int AARCH64GPRegister::mappings[][3] = {
    {R0, ARM64_REG_W0,  ARM64_REG_X0},
    {R1, ARM64_REG_W1,  ARM64_REG_X1},
    {R2, ARM64_REG_W2,  ARM64_REG_X2},
    {R3, ARM64_REG_W3,  ARM64_REG_X3},
    {R4, ARM64_REG_W4,  ARM64_REG_X4},
    {R5, ARM64_REG_W5,  ARM64_REG_X5},
    {R6, ARM64_REG_W6,  ARM64_REG_X6},
    {R7, ARM64_REG_W7,  ARM64_REG_X7},
    {R8, ARM64_REG_W8,  ARM64_REG_X8},
    {R9, ARM64_REG_W9,  ARM64_REG_X9},
    {R10, ARM64_REG_W10, ARM64_REG_X10},
    {R11, ARM64_REG_W11, ARM64_REG_X11},
    {R12, ARM64_REG_W12, ARM64_REG_X12},
    {R13, ARM64_REG_W13, ARM64_REG_X13},
    {R14, ARM64_REG_W14, ARM64_REG_X14},
    {R15, ARM64_REG_W15, ARM64_REG_X15},
    {R16, ARM64_REG_W16, ARM64_REG_X16},
    {R17, ARM64_REG_W17, ARM64_REG_X17},
    {R18, ARM64_REG_W18, ARM64_REG_X18},
    {R19, ARM64_REG_W19, ARM64_REG_X19},
    {R20, ARM64_REG_W20, ARM64_REG_X20},
    {R21, ARM64_REG_W21, ARM64_REG_X21},
    {R22, ARM64_REG_W22, ARM64_REG_X22},
    {R23, ARM64_REG_W23, ARM64_REG_X23},
    {R24, ARM64_REG_W24, ARM64_REG_X24},
    {R25, ARM64_REG_W25, ARM64_REG_X25},
    {R26, ARM64_REG_W26, ARM64_REG_X26},
    {R27, ARM64_REG_W27, ARM64_REG_X27},
    {R28, ARM64_REG_W28, ARM64_REG_X28},
    {R29, ARM64_REG_W29, ARM64_REG_X29},
    {R30, ARM64_REG_W30, ARM64_REG_X30},
    {R31, ARM64_REG_WSP, ARM64_REG_SP},
    {R31, ARM64_REG_WZR, ARM64_REG_XZR},
};

const int AARCH64GPRegister::fpMappings[][6] = {
    {V0,  ARM64_REG_Q0,  ARM64_REG_D0,  ARM64_REG_S0,  ARM64_REG_H0,  ARM64_REG_B0},
    {V1,  ARM64_REG_Q1,  ARM64_REG_D1,  ARM64_REG_S1,  ARM64_REG_H1,  ARM64_REG_B1},
    {V2,  ARM64_REG_Q2,  ARM64_REG_D2,  ARM64_REG_S2,  ARM64_REG_H2,  ARM64_REG_B2},
    {V3,  ARM64_REG_Q3,  ARM64_REG_D3,  ARM64_REG_S3,  ARM64_REG_H3,  ARM64_REG_B3},
    {V4,  ARM64_REG_Q4,  ARM64_REG_D4,  ARM64_REG_S4,  ARM64_REG_H4,  ARM64_REG_B4},
    {V5,  ARM64_REG_Q5,  ARM64_REG_D5,  ARM64_REG_S5,  ARM64_REG_H5,  ARM64_REG_B5},
    {V6,  ARM64_REG_Q6,  ARM64_REG_D6,  ARM64_REG_S6,  ARM64_REG_H6,  ARM64_REG_B6},
    {V7,  ARM64_REG_Q7,  ARM64_REG_D7,  ARM64_REG_S7,  ARM64_REG_H7,  ARM64_REG_B7},
    {V8,  ARM64_REG_Q8,  ARM64_REG_D8,  ARM64_REG_S8,  ARM64_REG_H8,  ARM64_REG_B8},
    {V9,  ARM64_REG_Q9,  ARM64_REG_D9,  ARM64_REG_S9,  ARM64_REG_H9,  ARM64_REG_B9},
    {V10, ARM64_REG_Q10, ARM64_REG_D10, ARM64_REG_S10, ARM64_REG_H10, ARM64_REG_B10},
    {V11, ARM64_REG_Q11, ARM64_REG_D11, ARM64_REG_S11, ARM64_REG_H11, ARM64_REG_B11},
    {V12, ARM64_REG_Q12, ARM64_REG_D12, ARM64_REG_S12, ARM64_REG_H12, ARM64_REG_B12},
    {V13, ARM64_REG_Q13, ARM64_REG_D13, ARM64_REG_S13, ARM64_REG_H13, ARM64_REG_B13},
    {V14, ARM64_REG_Q14, ARM64_REG_D14, ARM64_REG_S14, ARM64_REG_H14, ARM64_REG_B14},
    {V15, ARM64_REG_Q15, ARM64_REG_D15, ARM64_REG_S15, ARM64_REG_H15, ARM64_REG_B15},
    {V16, ARM64_REG_Q16, ARM64_REG_D16, ARM64_REG_S16, ARM64_REG_H16, ARM64_REG_B16},
    {V17, ARM64_REG_Q17, ARM64_REG_D17, ARM64_REG_S17, ARM64_REG_H17, ARM64_REG_B17},
    {V18, ARM64_REG_Q18, ARM64_REG_D18, ARM64_REG_S18, ARM64_REG_H18, ARM64_REG_B18},
    {V19, ARM64_REG_Q19, ARM64_REG_D19, ARM64_REG_S19, ARM64_REG_H19, ARM64_REG_B19},
    {V20, ARM64_REG_Q20, ARM64_REG_D20, ARM64_REG_S20, ARM64_REG_H20, ARM64_REG_B20},
    {V21, ARM64_REG_Q21, ARM64_REG_D21, ARM64_REG_S21, ARM64_REG_H21, ARM64_REG_B21},
    {V22, ARM64_REG_Q22, ARM64_REG_D22, ARM64_REG_S22, ARM64_REG_H22, ARM64_REG_B22},
    {V23, ARM64_REG_Q23, ARM64_REG_D23, ARM64_REG_S23, ARM64_REG_H23, ARM64_REG_B23},
    {V24, ARM64_REG_Q24, ARM64_REG_D24, ARM64_REG_S24, ARM64_REG_H24, ARM64_REG_B24},
    {V25, ARM64_REG_Q25, ARM64_REG_D25, ARM64_REG_S25, ARM64_REG_H25, ARM64_REG_B25},
    {V26, ARM64_REG_Q26, ARM64_REG_D26, ARM64_REG_S26, ARM64_REG_H26, ARM64_REG_B26},
    {V27, ARM64_REG_Q27, ARM64_REG_D27, ARM64_REG_S27, ARM64_REG_H27, ARM64_REG_B27},
    {V28, ARM64_REG_Q28, ARM64_REG_D28, ARM64_REG_S28, ARM64_REG_H28, ARM64_REG_B28},
    {V29, ARM64_REG_Q29, ARM64_REG_D29, ARM64_REG_S29, ARM64_REG_H29, ARM64_REG_B29},
    {V30, ARM64_REG_Q30, ARM64_REG_D30, ARM64_REG_S30, ARM64_REG_H30, ARM64_REG_B30},
    {V31, ARM64_REG_Q31, ARM64_REG_D31, ARM64_REG_S31, ARM64_REG_H31, ARM64_REG_B31},
};

int AARCH64GPRegister::convertToPhysicalINT(int id) {
    unsigned int guess = id - ARM64_REG_W0;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][1] == id) {
            return mappings[guess][0];
        }
    }
    guess = id - ARM64_REG_X0;
    if(guess < sizeof(mappings)/sizeof(*mappings)) {
        if(mappings[guess][2] == id) {
            return mappings[guess][0];
        }
    }

    for(size_t i = 0; i < sizeof(mappings)/sizeof(*mappings); i ++) {
        for(size_t j = 1; j < sizeof(*mappings)/sizeof(**mappings); j ++) {
            if(mappings[i][j] == id) {
                return mappings[i][0];
            }
        }
    }

    return AARCH64GPRegister::INVALID;
}

int AARCH64GPRegister::convertToPhysicalFP(int id) {
    unsigned int guess = id - ARM64_REG_Q0;
    if(guess < sizeof(fpMappings)/sizeof(*fpMappings)) {
        if(fpMappings[guess][1] == id) {
            return fpMappings[guess][0];
        }
    }
    guess = id - ARM64_REG_D0;
    if(guess < sizeof(fpMappings)/sizeof(*fpMappings)) {
        if(fpMappings[guess][2] == id) {
            return fpMappings[guess][0];
        }
    }
    guess = id - ARM64_REG_S0;
    if(guess < sizeof(fpMappings)/sizeof(*fpMappings)) {
        if(fpMappings[guess][3] == id) {
            return fpMappings[guess][0];
        }
    }
    guess = id - ARM64_REG_H0;
    if(guess < sizeof(fpMappings)/sizeof(*fpMappings)) {
        if(fpMappings[guess][4] == id) {
            return fpMappings[guess][0];
        }
    }
    guess = id - ARM64_REG_B0;
    if(guess < sizeof(fpMappings)/sizeof(*fpMappings)) {
        if(fpMappings[guess][5] == id) {
            return fpMappings[guess][0];
        }
    }

    for(size_t i = 0; i < sizeof(fpMappings)/sizeof(*fpMappings); i ++) {
        for(size_t j = 1; j < sizeof(*fpMappings)/sizeof(**fpMappings); j ++) {
            if(fpMappings[i][j] == id) {
                return fpMappings[i][0];
            }
        }
    }

    return AARCH64GPRegister::INVALID;
}

int AARCH64GPRegister::convertToPhysical(int id) {
    auto asInt = convertToPhysicalINT(id);
    if(asInt == AARCH64GPRegister::INVALID) {
        return convertToPhysicalFP(id);
    }
    return asInt;
}

size_t AARCH64GPRegister::getWidth(int pid, int id) {
    if(pid <= R31) {
        if(mappings[pid][1] == id) {
            return 4;
        }
        else if(pid == R31 && mappings[REGISTER_NUMBER][1] == id) {
            return 4;
        }
        return 8;
    }
    else {
        if(fpMappings[pid - V0][1] == id) {
            return 16;
        }
        else if(fpMappings[pid - V0][2] == id) {
            return 8;
        }
        else if(fpMappings[pid - V0][3] == id) {
            return 4;
        }
        else if(fpMappings[pid - V0][4] == id) {
            return 2;
        }
        else {
            return 1;
        }
    }

}
#endif
