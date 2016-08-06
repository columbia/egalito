#ifndef EGALITO_LOG_LOG_H
#define EGALITO_LOG_LOG_H

#include <stdio.h>
#include <string>
#include <iostream>  // for operator <<
#include "defaults.h"

class LogLevelSettings {
private:
    const char *file;
    std::string prefix;
    int bound;
public:
    LogLevelSettings(const char *file, const char *shortFile,
        int initialBound);
    bool shouldShow(int level) const { return level <= bound; }
    const char *getPrefix() const { return prefix.c_str(); }
    void setBound(int b) { this->bound = b; }

    // for debugging
    const char *getFile() const { return file; }
    int getBound() const { return bound; }
};

int _log_fprintf(FILE *stream, const char *type, const char *format, ...);
std::ostream &_log_stream();

#if defined(DEBUG) && DEBUG >= 0
    #define LOGGING_PRELUDE(shortName) \
        static LogLevelSettings _logLevels(__FILE__, shortName, DEBUG)
    #define LOGTYPE() \
        _logLevels.getPrefix()
    #define IF_LOG(level) \
        if(_logLevels.shouldShow(level))

    #define LOG(level, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                _log_stream() << __VA_ARGS__ << '\n'; \
            } \
        } while(0)
    #define LOG0(level, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                _log_stream() << __VA_ARGS__; \
            } \
        } while(0)

    #define CLOG(level, format, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                _log_fprintf(stdout, _logLevels.getPrefix(), \
                    format, ##__VA_ARGS__); \
            } \
        } while(0)
    #define CLOG0(level, format, ...) \
        do { \
            if(_logLevels.shouldShow(level)) { \
                std::printf(format, ##__VA_ARGS__); \
            } \
        } while(0)
#else
    #define LOGGING_PRELUDE(shortName)  /* nothing */
    #define LOGTYPE() ""
    #define IF_LOG(level) if(0)

    #define LOG(level, ...)             /* nothing */
    #define LOG0(level, ...)            /* nothing */
    #define CLOG(level, ...)            /* nothing */
    #define CLOG0(level, ...)           /* nothing */
#endif

#endif
