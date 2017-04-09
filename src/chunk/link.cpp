#include "link.h"
#include "chunk.h"
#include "plt.h"
#include "jumptable.h"
#include "elf/reloc.h"

address_t NormalLink::getTargetAddress() const {
    return target->getAddress();
}

address_t OffsetLink::getTargetAddress() const {
    return target->getAddress() + offset;
}

address_t PLTLink::getTargetAddress() const {
    return pltTrampoline->getAddress();
}

ChunkRef JumpTableLink::getTarget() const {
    return jumpTable;
}

address_t JumpTableLink::getTargetAddress() const {
    return jumpTable->getAddress();
}

address_t DataOffsetLink::getTargetAddress() const {
    return elf->getBaseAddress() + target;
}
