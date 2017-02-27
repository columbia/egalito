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
#else
    #define INVALID_REGISTER    ARM64_REG_INVALID
#endif

#endif
