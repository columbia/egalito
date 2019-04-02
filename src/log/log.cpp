#include <stdarg.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "log.h"
#include "registry.h"

LogLevelSetting::LogLevelSetting(const char *group,
    int initialBound) : bound(initialBound) {

    GroupRegistry::getInstance()->addGroup(group, initialBound, this);
}

#define DEFAULT_STREAM (&std::cout)
std::ostream *LogStream::output = DEFAULT_STREAM;

void LogStream::overrideStream(std::ostream *out) {
    output = (out ? out : DEFAULT_STREAM);
}

int _log_printf(const char *format, ...) {
    va_list args;
    int ret = 0;
    if(LogStream::getStream() == DEFAULT_STREAM) {
        va_start(args, format);
        ret = vfprintf(stdout, format, args);
        va_end(args);
    }
    else {
        char buffer[4096];
        va_start(args, format);
        ret = vsnprintf(buffer, sizeof buffer, format, args);
        va_end(args);

        (*LogStream::getStream()) << buffer;
    }

    return ret;
}

int _log_printf_n(const char *format, ...) {
    va_list args;
    char buffer[4096];
    int ret = 0;
    if(LogStream::getStream() == DEFAULT_STREAM) {
        size_t len = strlen(format);
        memcpy(buffer, format, len);
        buffer[len++] = '\n';
        buffer[len] = 0;

        va_start(args, format);
        ret = vfprintf(stdout, buffer, args);
        va_end(args);
    }
    else {
        va_start(args, format);
        ret = vsnprintf(buffer, sizeof buffer, format, args);
        va_end(args);

        (*LogStream::getStream()) << buffer << '\n';
    }

    return ret;
}

std::ostream &_log_stream() {
    return *LogStream::getStream();
}
