#include "link.h"
#include "chunk.h"

address_t NormalLink::getTargetAddress() const {
    return target->getAddress();
}
