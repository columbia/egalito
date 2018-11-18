#ifndef EGALITO_LOAD_DATA_H
#define EGALITO_LOAD_DATA_H

#include "types.h"

class DataRegion;

class DataLoader {
public:
#ifdef USE_LOADER
    /** Returns thread pointer for this platform's TLS.
        offset will be incremented by the size of the header.
    */
    address_t allocateTLS(address_t base, size_t size, size_t *offset);
#endif
    void loadRegion(DataRegion *region);
    address_t loadRegionTo(address_t address, DataRegion *region);
};

#endif
