#include "link.h"
#include "chunk.h"
#include "plt.h"
#include "jumptable.h"
#include "dataregion.h"
#include "module.h"
#include "marker.h"
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

address_t MarkerLink::getTargetAddress() const {
    return marker->getAddress();
}

ChunkRef DataOffsetLink::getTarget() const {
    return section;
}

address_t DataOffsetLink::getTargetAddress() const {
    return section->getAddress() + target;
}

ChunkRef TLSDataOffsetLink::getTarget() const {
    return tls;
}

address_t TLSDataOffsetLink::getTargetAddress() const {
    return tls->getTLSOffset() + target;
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

    return module->getDataRegionList()->createDataLink(
        target, module, nullptr, isRelative);
}
