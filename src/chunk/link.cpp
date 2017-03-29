#include "link.h"
#include "chunk.h"
#include "plt.h"
#include "elf/reloc.h"

address_t NormalLink::getTargetAddress() const {
    return target->getAddress();
}

address_t OffsetLink::getTargetAddress() const {
    return target->getAddress() + offset;
}

address_t PLTLink::getTargetAddress() const {
#ifdef AARCH_X86_64
    return pltTrampoline->getSourceElf()->getBaseAddress() + originalAddress;
#else
    return pltTrampoline->getAddress();
#endif
}

address_t DataOffsetLink::getTargetAddress() const {
    return elf->getBaseAddress() + target;
}
