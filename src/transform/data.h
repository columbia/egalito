#ifndef EGALITO_LOAD_DATA_H
#define EGALITO_LOAD_DATA_H

#include "types.h"

class ElfMap;
class DataRegion;

class DataLoader {
private:
    ElfMap *elfMap;
public:
    DataLoader(ElfMap *elfMap) : elfMap(elfMap) {}
    void *mapTLS(DataRegion *tls, address_t baseAddress);
private:
    void copyTLSData(DataRegion *tls, address_t loadAddress);
};

#endif
