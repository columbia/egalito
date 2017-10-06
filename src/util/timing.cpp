#include <iomanip>
#include "timing.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dtiming
#include "log/log.h"

EgalitoTiming::EgalitoTiming(const char *message, unsigned long printThresholdMS)
    : message(message), printThresholdMS(printThresholdMS) {

    startTime = std::chrono::high_resolution_clock::now();
}

EgalitoTiming::~EgalitoTiming() {
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>
        (endTime - startTime).count();

    if(static_cast<unsigned long>(duration / 1000) >= printThresholdMS) {
        CLOG(1, "TIMING: %8.6fs for \"%s\"", duration / 1e6, message);
    }
}
