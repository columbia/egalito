#include <stdarg.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "log.h"
#include "registry.h"

LogLevelSetting::LogLevelSetting(const char *group,
    int initialBound) : bound(initialBound) {

    GroupRegistry::getInstance()->addGroup(group, initialBound, this);
}

int _log_fprintf(FILE *stream, const char *format, ...) {
    va_list args;

    char buffer[4096] = {0};
    snprintf(buffer, sizeof buffer, "%s\n", format);

    va_start(args, format);
    int ret = vfprintf(stream, buffer, args);
    va_end(args);

    return ret;
}

std::ostream &_log_stream() {
    return std::cout;
}
