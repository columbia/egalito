#include <cassert>
#include "link.h"
#include "chunk/concrete.h"
#include "chunk/aliasmap.h"
#include "conductor/conductor.h"
#include "conductor/bridge.h"
#include "disasm/disassemble.h"
#include "elf/reloc.h"
#include "elf/elfspace.h"
#include "load/emulator.h"
#include "operation/find.h"
#include "operation/mutator.h"

#include "log/log.h"
#include "log/temp.h"
#include "chunk/dump.h"

address_t NormalLinkBase::getTargetAddress() const {
    return target->getAddress();
}

address_t OffsetLink::getTargetAddress() const {
    return target->getAddress() + offset;
}

ChunkRef PLTLink::getTarget() const {
    return pltTrampoline;
}

address_t PLTLink::getTargetAddress() const {
    return pltTrampoline->getAddress();
}

ChunkRef ExternalSymbolLink::getTarget() const {
    return externalSymbol->getResolved();
}

address_t ExternalSymbolLink::getTargetAddress() const {
    auto resolved = externalSymbol->getResolved();
    return resolved ? resolved->getAddress() : 0;
}

ChunkRef CopyRelocLink::getTarget() const {
    return externalSymbol->getResolved();
}

address_t CopyRelocLink::getTargetAddress() const {
    auto resolved = externalSymbol->getResolved();
    return resolved ? resolved->getAddress() : 0;
}

ChunkRef JumpTableLink::getTarget() const {
    return jumpTable;
}

address_t JumpTableLink::getTargetAddress() const {
    return jumpTable->getAddress();
}

address_t EgalitoLoaderLink::getTargetAddress() const {
    return LoaderBridge::getInstance()->getAddress(targetName);
}

address_t MarkerLinkBase::getTargetAddress() const {
    return marker->getAddress();
}

ChunkRef GSTableLink::getTarget() const {
    return entry->getTarget();
}

address_t GSTableLink::getTargetAddress() const {
    return entry->getOffset();
}

ChunkRef DistanceLink::getTarget() const {
    return target;
}

address_t DistanceLink::getTargetAddress() const {
    return target->getAddress() + target->getSize() - base->getAddress();
}

ChunkRef DataOffsetLinkBase::getTarget() const {
    return section;
}

address_t DataOffsetLinkBase::getTargetAddress() const {
    return section->getAddress() + target + addend;
}

ChunkRef TLSDataOffsetLink::getTarget() const {
    LOG(1, "calling TLSDataOffsetLink::getTarget(), "
        "target equals " << (tls ? tls->getName() : "NULL"));
    return tls;
}

address_t TLSDataOffsetLink::getTargetAddress() const {
    if(!tls) return 0;
    LOG(1, "calling TLSDataOffsetLink::getTargetAddress(), "
        "target equals " << std::hex << tls->getTLSOffset()
        << " + " << target);
    return tls->getTLSOffset() + target;
}

Link *LinkFactory::makeNormalLink(ChunkRef target, bool isRelative,
    bool isExternal) {

    if(isRelative) {
        return new NormalLink(target, isExternal
            ? Link::SCOPE_EXTERNAL_JUMP : Link::SCOPE_INTERNAL_JUMP);
    }
    else {
        return new AbsoluteNormalLink(target, isExternal
            ? Link::SCOPE_EXTERNAL_JUMP : Link::SCOPE_INTERNAL_JUMP);
    }
}

Link *LinkFactory::makeDataLink(Module *module, address_t target,
    bool isRelative) {

    return module->getDataRegionList()->createDataLink(
        target, module, isRelative);
}

Link *LinkFactory::makeMarkerLink(Module *module, Symbol *symbol, size_t addend,
    bool isRelative) {

    return module->getMarkerList()->createMarkerLink(
        symbol, addend, module, isRelative);
}

Link *LinkFactory::makeInferredMarkerLink(Module *module, address_t address,
    bool isRelative) {

    return module->getMarkerList()->createInferredMarkerLink(
        address, module, isRelative);
}
