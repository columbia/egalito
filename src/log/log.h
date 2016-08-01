#ifndef EGALITO_LOG_LOG_H
#define EGALITO_LOG_LOG_H

#include "defaults.h"

#if defined(DEBUG) && DEBUG > 0
    #define LOG(level, ...) \
        do { \
            if(level < DEBUG) std::cout << __VA_ARGS__; \
        } while(0)
#else
    #define LOG(level, ...)  /* nothing */
#endif

#endif
