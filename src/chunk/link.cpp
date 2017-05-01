#include "link.h"
#include "chunk.h"
#include "plt.h"
#include "jumptable.h"
#include "dataregion.h"
#include "module.h"
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

ChunkRef DataOffsetLink::getTarget() const {
    return region;
}

address_t DataOffsetLink::getTargetAddress() const {
    return region->getAddress() + target;
}

Link *LinkFactory::makeNormalLink(ChunkRef target, bool isRelative,
    bool isExternal) {

    if(!isExternal) {
        if(isRelative) {
            return new NormalLink(target);
        }
        else {
            return new AbsoluteNormalLink(target);
        }
    }
    else {
        if(isRelative) {
            return new ExternalNormalLink(target);
        }
        else {
            return new ExternalAbsoluteNormalLink(target);
        }
    }
}

Link *LinkFactory::makeDataLink(Module *module, address_t target,
    bool isRelative) {

    return module->getDataRegionList()->createDataLink(target, isRelative);
}
