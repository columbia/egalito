#ifndef EGALITO_EXEFILE_EXEMAP_H
#define EGALITO_EXEFILE_EXEMAP_H

#include <string>
#include "types.h"

class ExeMap {
public:
    virtual ~ExeMap() {}

    virtual address_t getBaseAddress() const = 0;
    virtual void setBaseAddress(address_t address) = 0;

    virtual address_t getEntryPoint() const = 0;
};

#endif
