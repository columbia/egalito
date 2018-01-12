#include <iomanip>
#include "timing.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dtiming
#include "log/log.h"

#include "cminus/print.h"

extern bool egalito_init_done;
EgalitoTiming::EgalitoTiming(const char *message, unsigned long printThresholdMS)
    : message(message), printThresholdMS(printThresholdMS) {

    startTime = std::chrono::high_resolution_clock::now();
}

EgalitoTiming::~EgalitoTiming() {
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>
        (endTime - startTime).count();

    if(static_cast<unsigned long>(duration / 1000) >= printThresholdMS) {
        if(!egalito_init_done) {
            CLOG(1, "TIMING: %8.6fs for \"%s\"", duration / 1e6, message);
        }
        else {
            egalito_printf("timing: %d ms %d us for \"%s\"\n",
                (int)(duration/1000), (int)(duration%1000), message);
        }
    }
}
