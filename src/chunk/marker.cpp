#include <string.h>
#include <cassert>
#include "config.h"
#include "marker.h"
#include "chunk/dataregion.h"
#include "chunk/module.h"
#include "chunk/visitor.h"
#include "elf/elfspace.h"
#include "elf/reloc.h"
#include "instr/concrete.h"
#include "operation/find.h"
#include "operation/find2.h"

#include "log/log.h"
#include "chunk/dump.h"

Marker::Marker(Chunk *base, size_t addend)
    : base(base), addend(addend) { }

address_t Marker::getAddress() const {
    return base->getAddress() + addend;
}

void Marker::setAddress(address_t address) {
    assert("Marker::setAddress() should not be called" && 0);
}

SectionStartMarker::SectionStartMarker(DataSection *dataSection)
    : Marker(nullptr, 0), dataSection(dataSection), bias(0) { }

address_t SectionStartMarker::getAddress() const {
    return dataSection->getAddress() + bias;
}

void SectionStartMarker::setAddress(address_t address) {
    bias = address - getAddress();
}

SectionEndMarker::SectionEndMarker(DataSection *dataSection)
    : Marker(nullptr, 0), dataSection(dataSection), bias(0) { }

address_t SectionEndMarker::getAddress() const {
    return dataSection->getAddress() + dataSection->getSize() + bias;
}

void SectionEndMarker::setAddress(address_t address) {
    bias = address - getAddress();
}

void MarkerList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

Link *MarkerList::createMarkerLink(Symbol *symbol, size_t addend,
    Module *module, bool isRelative) {

    //assert(symbol);
    if(!symbol) return nullptr;
    assert(symbol->getSectionIndex() != 0);
    if(symbol->getType() == Symbol::TYPE_TLS) return nullptr;

    LOG(10, "creating marker link to " << symbol->getName() << " + " << addend
        << " in " << module->getName());

    if(symbol->getType() == Symbol::TYPE_SECTION) {
        auto address = symbol->getAddress();
        auto region = module->getDataRegionList()->findRegionContaining(address);
        auto dsec = region->findDataSectionContaining(address);
        if(address + addend == region->getAddress()) {
            assert("shouldn't this be a DataOffsetLink?" && 0);
            return createStartMarkerLink(dsec, module, isRelative);
        }
        else if(address + addend == region->getAddress() + region->getSize()) {
            return createEndMarkerLink(dsec, module, isRelative);
        }

        // adjust addend to be relative to the section
        // (this is safe as we do not transform data)

        addend += symbol->getAddress() - dsec->getAddress();

        return createGeneralMarkerLink(dsec, addend, module, isRelative);
    }

    if(auto b = ChunkFind2().findFunctionInModule(symbol->getName(), module)) {
        return createGeneralMarkerLink(b, addend, module, isRelative);
    }

#ifndef LINUX_KERNEL_MODE
    // during Linux kernel boot, a pointer must point to a strage address
    // just leave the original
    assert("couldn't find the base of marker..." && 0);
#endif
    return nullptr;
}

Link *MarkerList::createInferredMarkerLink(address_t address,
    Module *module, bool isRelative) {

    // if found, it's usually a gap inside a region
    auto region = module->getDataRegionList()->findRegionContaining(address);
    assert(!region || !region->findDataSectionContaining(address));

    // usually pointing to the end of .bss (other cases like kernel require -q)
    if(!region) {
        region = module->getDataRegionList()->findRegionContaining(address - 1);
    }
    if(region) {
        DataSection *base = nullptr;
        for(auto dsec : CIter::children(region)) {
            if(address < dsec->getAddress()) break;
            base = dsec;
        }
        size_t addend = address - base->getAddress();
        return createGeneralMarkerLink(base, addend, module, isRelative);
    }
    return nullptr;
}

static Link *makeMarkerLink(Marker *marker, bool isRelative) {
    if(isRelative) {
        return new MarkerLink(marker);
    }
    else {
        return new AbsoluteMarkerLink(marker);
    }
}

Link *MarkerList::createGeneralMarkerLink(Chunk *base,
    size_t addend, Module *module, bool isRelative) {

    LOG(10, "    general markerLink");
    auto list = module->getMarkerList();
    auto marker = list->addGeneralMarker(base, addend);
    return makeMarkerLink(marker, isRelative);
}

Link *MarkerList::createStartMarkerLink(
    DataSection *dataSection, Module *module, bool isRelative) {

    LOG(10, "    start markerLink");
    auto list = module->getMarkerList();
    auto marker = list->addStartMarker(dataSection);
    return makeMarkerLink(marker, isRelative);
}

Link *MarkerList::createEndMarkerLink(
    DataSection *dataSection, Module *module, bool isRelative) {

    LOG(10, "    end markerLink");
    auto list = module->getMarkerList();
    auto marker = list->addEndMarker(dataSection);
    return makeMarkerLink(marker, isRelative);
}

Marker *MarkerList::addGeneralMarker(Chunk *base, size_t addend) {
    auto marker = new Marker(base, addend);
    getChildren()->add(marker);
    return marker;
}

Marker *MarkerList::addStartMarker(DataSection *dataSection) {
    auto marker = new SectionStartMarker(dataSection);
    getChildren()->add(marker);
    return marker;
}

Marker *MarkerList::addEndMarker(DataSection *dataSection) {
    auto marker = new SectionEndMarker(dataSection);
    getChildren()->add(marker);
    return marker;
}

