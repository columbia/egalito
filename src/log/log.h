#ifndef EGALITO_LOG_LOG_H
#define EGALITO_LOG_LOG_H

#include <stdio.h>
#include <string>
#include "defaults.h"

class LogLevelSettings {
private:
    const char *file;
    std::string prefix;
    int bound;
public:
    LogLevelSettings(const char *file, const char *shortFile,
        int initialBound);
    bool shouldShow(int level) const { return level < bound; }
    const char *getPrefix() const { return prefix.c_str(); }
};

int _log_fprintf(FILE *stream, const char *type, const char *format, ...);

#if defined(DEBUG) && DEBUG > 0
    #define LOGGING_PRELUDE(shortName) \
        static LogLevelSettings _logLevels(__FILE__, shortName, DEBUG)

    #define LOG(level, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                std::cout << _logLevels.getPrefix() \
                    << __VA_ARGS__ << '\n'; \
            } \
        } while(0)
    #define LOG0(level, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                std::cout << __VA_ARGS__; \
            } \
        } while(0)

    #define CLOG(level, format, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                _log_fprintf(stdout, _logLevels.getPrefix(), \
                    format, __VA_ARGS__); \
            } \
        } while(0)
    #define CLOG0(level, format, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                std::printf(format, __VA_ARGS__); \
            } \
        } while(0)
#else
    #define LOGGING_PRELUDE(shortName)  /* nothing */
    #define LOG(level, ...)             /* nothing */
    #define LOG0(level, ...)            /* nothing */
    #define CLOG(level, ...)            /* nothing */
    #define CLOG0(level, ...)           /* nothing */
#endif

#endif
