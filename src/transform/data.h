#ifndef EGALITO_LOAD_DATA_H
#define EGALITO_LOAD_DATA_H

#include "types.h"

class ElfMap;
class DataRegion;

class DataLoader {
private:
    address_t tlsBaseAddress;
public:
    DataLoader(address_t tlsBaseAddress)
        : tlsBaseAddress(tlsBaseAddress) {}

    /** Returns thread pointer for this platform's TLS.
        offset will be incremented by the size of the header.
    */
    address_t allocateTLS(size_t size, size_t *offset);
    void loadRegion(ElfMap *elfMap, DataRegion *region);
};

#endif
