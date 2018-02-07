#ifndef EGALITO_CONFIG_H
#define EGALITO_CONFIG_H
#include "../config/config.h"

#ifndef EGALITO_PATH
    // unless overridden here, will look for libegalito in the same
    // directory that the etshell/loader executable is run from
    //#define EGALITO_PATH    "./libegalito.so"
#endif

// just to make the code compile
#ifndef LINUX_KERNEL_BASE
    #define LINUX_KERNEL_BASE   0
#endif
#ifndef LINUX_KERNEL_CODE_BASE
    #define LINUX_KERNEL_CODE_BASE  0
#endif
#endif
