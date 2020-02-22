#ifndef EGALITO_PASS_RUN_H
#define EGALITO_PASS_RUN_H

#include "util/timing.h"

#if 1  // enable pass profiling
    #define RUN_PASS(passConstructor, module) \
        { \
            EgalitoTiming timing(#passConstructor); \
            auto pass = passConstructor; \
            module->accept(&pass); \
        }
#else
    #define RUN_PASS(passConstructor, module) \
        { \
            auto pass = passConstructor; \
            module->accept(&pass); \
        }
#endif

#endif
