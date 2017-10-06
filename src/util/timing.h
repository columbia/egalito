#ifndef EGALITO_UTIL_TIMING_H
#define EGALITO_UTIL_TIMING_H

#include <chrono>

class EgalitoTiming {
private:
    std::chrono::high_resolution_clock::time_point startTime;
    const char *message;
public:
    EgalitoTiming(const char *message);
    ~EgalitoTiming();
};

#endif
