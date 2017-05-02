#ifndef EGALITO_DISASM_REGISTER_H
#define EGALITO_DISASM_REGISTER_H

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
#else
    #define INVALID_REGISTER    ARM64_REG_INVALID
    #define CONDITION_REGISTER  ARM64_REG_NZCV
    #define REGISTER_ENDING     ARM64_REG_ENDING
#endif

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
class AARCH64GPRegister {
public:
    enum ID {
        INVALID = -1,
        R0 = 0, R1, R2, R3, R4, R5, R6, R7,
        R8,  R9,  R10, R11, R12, R13, R14, R15,
        R16, R17, R18, R19, R20, R21, R22, R23,
        R24, R25, R26, R27, R28, R29, R30, R31,

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
        R_TEMPORARY_END = R18
    };

private:
    int _id;
public:
    AARCH64GPRegister(int id, bool physical)
        : _id(id) { if(!physical) _id = convertToPhysical(id); }
    int id() const { return _id; }
    unsigned int encoding() const { return static_cast<unsigned int>(_id); }
    //private:
    int convertToPhysical(int id);
};

inline AARCH64GPRegister::ID& operator++(AARCH64GPRegister::ID &orig) {
    orig = static_cast<AARCH64GPRegister::ID>(orig + 1);
    if(orig > AARCH64GPRegister::REGISTER_NUMBER) throw "can't ++R31";
    return orig;
}

template <typename RegisterType>
class PhysicalRegister {
private:
    RegisterType reg;
public:
    PhysicalRegister(int id, bool physical) : reg(id, physical) {}
    int id() const { return reg.id(); }
    unsigned int encoding() const { return reg.encoding(); }
    inline bool operator==(const PhysicalRegister& rhs) {
        return id() == rhs.id(); }
};
#endif

#endif
