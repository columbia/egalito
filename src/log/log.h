#ifndef EGALITO_LOG_LOG_H
#define EGALITO_LOG_LOG_H

#include <stdio.h>
#include <string>
#include <iostream>  // for operator <<
#include "defaults.h"

/* Any file which wishes to use logging must define DEBUG_GROUP
    as some lower-case string foo, and ensure that D_foo exists in
    defaults.h and is set to some number.

    To change the logging group, any file may undefine DEBUG_GROUP
    and re-define it prior to including this header file.
*/

class LogLevelSetting {
private:
    int bound;
public:
    LogLevelSetting(const char *group, int initialBound);
    bool shouldShow(int level) const { return level <= bound; }
    void setBound(int b) { this->bound = b; }

    // for debugging
    int getBound() const { return bound; }
};

class LogStream {
private:
    static std::ostream *output;
public:
    static std::ostream *getStream() { return output; }

    // pass out=nullptr to reset to standard output
    static void overrideStream(std::ostream *out);
};

int _log_printf(const char *format, ...);
int _log_printf_n(const char *format, ...);
std::ostream &_log_stream();

#define _APPEND(x, y) x ## y
#define _APPEND2(x, y) _APPEND(x, y)
#define DEBUG_LEVEL _APPEND2(D_, DEBUG_GROUP)

#define _STRINGIZE(x) # x
#define _STRINGIZE2(x) _STRINGIZE(x)
#define DEBUG_GROUP_NAME _STRINGIZE2(DEBUG_GROUP)

#if defined(DEBUG_LEVEL) && DEBUG_LEVEL >= 0
    #define LOGGING_PRELUDE() \
        static LogLevelSetting _logLevel( \
            DEBUG_GROUP_NAME, DEBUG_LEVEL)
    #define IF_LOG(level) \
        if(_logLevel.shouldShow(level))

    #define LOG(level, ...) \
        do { \
            if(_logLevel.shouldShow(level)) { \
                _log_stream() << __VA_ARGS__ << '\n'; \
            } \
        } while(0)
    #define LOG0(level, ...) \
        do { \
            if(_logLevel.shouldShow(level)) { \
                _log_stream() << __VA_ARGS__; \
            } \
        } while(0)

    #define CLOG(level, format, ...) \
        do { \
            if(_logLevel.shouldShow(level)) { \
                _log_printf_n(format, ##__VA_ARGS__); \
            } \
        } while(0)
    #define CLOG0(level, format, ...) \
        do { \
            if(_logLevel.shouldShow(level)) { \
                _log_printf(format, ##__VA_ARGS__); \
            } \
        } while(0)
#else
    #define LOGGING_PRELUDE(group)      /* nothing */
    #define IF_LOG(level) if(0)

    #define LOG(level, ...)             /* nothing */
    #define LOG0(level, ...)            /* nothing */
    #define CLOG(level, ...)            /* nothing */
    #define CLOG0(level, ...)           /* nothing */
#endif

LOGGING_PRELUDE();

#endif
