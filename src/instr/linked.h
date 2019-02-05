#ifdef ARCH_X86_64
    #include "instr/linked-x86_64.h"
#elif defined(ARCH_AARCH64)
    #include "instr/linked-aarch64.h"
#elif defined(ARCH_RISCV)
    #include "instr/linked-riscv.h"
#else
    #error "No linked instructions header for current arch!"
#endif
