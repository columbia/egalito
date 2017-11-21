#ifndef EGALITO_INSTR_REGISTER_H
#define EGALITO_INSTR_REGISTER_H

#include <capstone/capstone.h>
#ifdef ARCH_X86_64
    #include <capstone/x86.h>
#else
    #include <capstone/arm64.h>
#endif

typedef
#ifdef ARCH_X86_64
    x86_reg
#else
    arm64_reg
#endif
    Register;

#ifdef ARCH_X86_64
    #define INVALID_REGISTER    X86_REG_INVALID
    #define CONDITION_REGISTER  X86_REG_EFLAGS
    #define REGISTER_ENDING     X86_REG_ENDING
    #define REGISTER_SP         X86_REG_RSP
    #define REGISTER_FP         X86_REG_RBP
#else
    #define INVALID_REGISTER    ARM64_REG_INVALID
    #define CONDITION_REGISTER  ARM64_REG_NZCV
    #define REGISTER_ENDING     ARM64_REG_ENDING
    #define REGISTER_SP         ARM64_REG_SP
    #define REGISTER_FP         ARM64_REG_FP
#endif

#ifdef ARCH_X86_64
class X86Register {
public:
    enum ID {
        INVALID = -1,
        R0 = 0, R1, R2, R3, R4, R5, R6, R7,
        R8, R9, R10, R11, R12, R13, R14, R15,

        REGISTER_NUMBER,

        BP = R5,
        SP = R4,

        FLAGS = REGISTER_NUMBER
    };

private:
    const static int mappings[R15 - R0 + 1][5];

public:
    static int convertToPhysical(int id);
    static size_t getWidth(int pid, int id);
    static int isInteger(int pid) { return (R0 <= pid && pid <= R15); }

private:
    static int convertToPhysicalINT(int id);
};
#endif

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
// rename this class
class AARCH64GPRegister {
public:
    // the IDs must be consecutive for the ones with the same prefix
    enum ID {
        INVALID = -1,
        R0 = 0, R1, R2, R3, R4, R5, R6, R7,
        R8,  R9,  R10, R11, R12, R13, R14, R15,
        R16, R17, R18, R19, R20, R21, R22, R23,
        R24, R25, R26, R27, R28, R29, R30, R31,

        V0, V1, V2, V3, V4, V5, V6, V7,
        V8,  V9,  V10, V11, V12, V13, V14, V15,
        V16, V17, V18, V19, V20, V21, V22, V23,
        V24, V25, V26, V27, V28, V29, V30, V31,

        REGISTER_NUMBER,

        IP0 = R16,
        IP1 = R17,
        FP = R29,
        LR = R30,
        SP = R31,
        R_CALLER_SAVED_BEGIN = R0,
        R_CALLER_SAVED_END = R7,
        R_CALLEE_SAVED_BEGIN = R19,
        R_CALLEE_SAVED_END = R28,
        // R8 is indirect result location register
        R_TEMPORARY_BEGIN = R9,
        R_TEMPORARY_END = R18,

        NZCV = REGISTER_NUMBER,
        ONETIME_NZCV
    };

private:
    int _id;
    const static int mappings[R31 - R0 + 1 + 1][3]; // last one for NZCV
    const static int fpMappings[V31 - V0 + 1][6];

public:
    AARCH64GPRegister(int id, bool physical)
        : _id(id) { if(!physical) _id = convertToPhysical(id); }
    int id() const { return _id; }
    // this doesn't work for FP registers
    unsigned int encoding() const { return static_cast<unsigned int>(_id); }

    static int convertToPhysical(int id);
    static size_t getWidth(int pid, int id);
    static int isInteger(int pid) { return (R0 <= pid && pid <= R31); }

private:
    static int convertToPhysicalINT(int id);
    static int convertToPhysicalFP(int id);
};

inline AARCH64GPRegister::ID& operator++(AARCH64GPRegister::ID &orig) {
    orig = static_cast<AARCH64GPRegister::ID>(orig + 1);
    if(orig > AARCH64GPRegister::REGISTER_NUMBER) throw "can't ++R31";
    return orig;
}
#endif

template <typename RegisterType>
class PhysicalRegister {
private:
    RegisterType reg;
public:
    PhysicalRegister(int id, bool physical) : reg(id, physical) {}
    int id() const { return reg.id(); }
    unsigned int encoding() const { return reg.encoding(); }
    bool operator==(const PhysicalRegister& rhs)
        { return id() == rhs.id(); }
};

#endif
