#include <sstream>
#include "platform.h"

static const char *registerNames[] = {
#ifdef ARCH_X86_64
    "rax", "rdx", "rcx", "rbx",
    "rsi", "rdi", "rbp", "rsp",
    "r8",  "r9",  "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rip",
    "xmm0",  "xmm1",  "xmm2",  "xmm3",
    "xmm4",  "xmm5",  "xmm6",  "xmm7",
    "xmm8",  "xmm9",  "xmm10", "xmm11",
    "xmm12", "xmm13", "xmm14", "xmm15",
    "st0", "st1", "st2", "st3",
    "st4", "st5", "st6", "st7",
    "mm0", "mm1", "mm2", "mm3",
    "mm4", "mm5", "mm6", "mm7",
    "rflags",
    "es", "cs", "ss", "ds", "fs", "gs", "", "",
    "fs.base", "gs.base", "", "",
    "tr", "ldtr",
    "mxcsr", "fcw", "fsw"
#else
    // please put aarch64 register names here, in DWARF order
#endif
};

std::string getRegisterName(unsigned int reg) {
    std::ostringstream stream;

    stream << "r" << reg;
    if(reg < sizeof(registerNames)/sizeof(*registerNames)) {
        stream << " (" << registerNames[reg] << ")";
    }

    return stream.str();
}

const char *shortRegisterName(unsigned int reg) {
    return (reg <= sizeof(registerNames)/sizeof(*registerNames))
        ? registerNames[reg] : "(unknown)";
}
