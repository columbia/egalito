#ifndef EGALITO_CHUNK_REGISTER_H
#define EGALITO_CHUNK_REGISTER_H

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

#endif
