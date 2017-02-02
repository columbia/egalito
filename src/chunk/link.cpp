#include "link.h"
#include "chunk.h"
#include "elf/reloc.h"

address_t NormalLink::getTargetAddress() const {
    return target->getAddress();
}

address_t PLTLink::getTargetAddress() const {
    return reloc->getAddress();
}
