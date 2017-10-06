#include "handle.h"

bool DisasmHandle::initialized[2] = {false, false};
csh DisasmHandle::handle[2];

DisasmHandle::DisasmHandle(bool detailed) {
    this->which = detailed ? 1 : 0;
    csh *h = &handle[which];
    if(!initialized[which]) {
#ifdef ARCH_X86_64
        if(cs_open(CS_ARCH_X86, CS_MODE_64, h) != CS_ERR_OK) {
            throw "Can't initialize capstone handle!";
        }
#elif defined(ARCH_AARCH64)
        if(cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, h) != CS_ERR_OK) {
            throw "Can't initialize capstone handle!";
        }
#elif defined(ARCH_ARM)
        if(cs_open(CS_ARCH_ARM, CS_MODE_ARM, h) != CS_ERR_OK) {
            throw "Can't initialize capstone handle!";
        }
#endif

        cs_option(*h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // AT&T syntax
        if(detailed) {
            cs_option(*h, CS_OPT_DETAIL, CS_OPT_ON);
        }

        initialized[which] = true;
    }
}

DisasmHandle::~DisasmHandle() {
    //cs_close(&handle);
}

