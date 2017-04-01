#ifndef EGALITO_LOAD_DATA_H
#define EGALITO_LOAD_DATA_H

#include "types.h"

class Module;

class DataLoader {
public:
    void *setupMainData(Module *module, address_t baseAddress);
    void loadLibraryTLSData(Module *module, address_t baseAddress);
};
#endif

