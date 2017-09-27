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
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
    "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
    "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
    "x30", "sp", "", "ELR_mode",
    //34 - 63: reserved
    "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "",
    "", "", "", "",
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9",
    "v10", "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19",
    "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29",
    "v30", "v31",
    //96-127: reserved
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
