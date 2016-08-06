#include <stdarg.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "log.h"
#include "registry.h"

#define LOG_TYPE_WIDTH 8

LogLevelSettings::LogLevelSettings(const char *file, const char *shortFile,
    int initialBound) : file(file), bound(initialBound) {

    FileRegistry::getInstance()->addFile(shortFile, this);

    std::ostringstream ss1;
    ss1 << "[" << shortFile << "] ";
    std::ostringstream ss2;
    ss2 << std::left << std::setw(LOG_TYPE_WIDTH) << ss1.str();
    prefix = ss2.str();
}

int _log_fprintf(FILE *stream, const char *type, const char *format, ...) {
    va_list args;

#if 0
    char buffer[4096] = {0};
    snprintf(buffer, sizeof buffer, "%s%s\n", type, format);
#else
    char buffer[4096] = {0};
    snprintf(buffer, sizeof buffer, "%s\n", format);
#endif

    va_start(args, format);
    int ret = vfprintf(stream, buffer, args);
    va_end(args);

    return ret;
}

std::ostream &_log_stream() {
    return std::cout;
}
