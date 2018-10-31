#ifndef EGALITO_TRANSFORM_SLOT_H
#define EGALITO_TRANSFORM_SLOT_H

#include "types.h"

class Slot {
private:
    address_t address;
    size_t size;
public:
    Slot(address_t address, size_t size)
        : address(address), size(size) {}
    address_t getAddress() const { return address; }
    size_t getSize() const { return size; }
};

#endif
