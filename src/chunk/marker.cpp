#include <string.h>
#include "marker.h"
#include "chunk/dataregion.h"
#include "chunk/module.h"
#include "chunk/visitor.h"
#include "elf/elfspace.h"
#include "elf/reloc.h"
#include "instr/concrete.h"
#include "operation/find.h"

#include "log/log.h"

Marker::Marker(address_t address, Symbol *symbol)
    : address(address), symbol(symbol) {
}

SectionStartMarker::SectionStartMarker(DataSection *dataSection, Symbol *symbol)
    : Marker(dataSection->getAddress(), symbol), dataSection(dataSection),
      bias(0) {
}

address_t SectionStartMarker::getAddress() const {
    return dataSection->getAddress() + bias;
}

void SectionStartMarker::setAddress(address_t address) {
    bias = address - getAddress();
}

SectionEndMarker::SectionEndMarker(DataSection *dataSection, Symbol *symbol)
    : Marker(dataSection->getAddress() + dataSection->getSize(), symbol),
      dataSection(dataSection), bias(0) {
}

address_t SectionEndMarker::getAddress() const {
    return dataSection->getAddress() + dataSection->getSize() + bias;
}

void SectionEndMarker::setAddress(address_t address) {
    bias = address - getAddress();
}

void MarkerList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

Link *MarkerList::createMarkerLink(address_t target, size_t addend,
    Symbol *symbol, Module *module) {

    LOG(10, "creating marker link to " << target
        << " in " << module->getName());
    if(symbol) {
        LOG(10, "    with symbol " << symbol->getName());
        auto sec = module->getElfSpace()->getElfMap()->findSection(
            symbol->getSectionIndex());
        if(sec == nullptr) {
            LOG(1, "can't find section for symbol [" << symbol->getName()
                << "] at address 0x" << std::hex << symbol->getAddress());
        }
        else {
            for(auto region : CIter::regions(module)) {
                for(auto dsec : CIter::children(region)) {
                    auto original
                        = region->getOriginalAddress() + dsec->getOriginalOffset();
                    if(original == sec->getVirtualAddress()) {
                        auto link = createStartOrEndMarkerLink(
                            target, symbol, addend, dsec, module);
                        if(link) return link;
                        // some markers have alignment restrictions
                    }
                }
            }
        }
    }
    else {
        for(auto region : CIter::regions(module)) {
            for(auto dsec : CIter::children(region)) {
                auto link = createStartOrEndMarkerLink(
                    target, symbol, addend, dsec, module);
                if(link) return link;
            }
        }
    }
    return createGeneralMarkerLink(target, symbol, addend, module);
}

Link *MarkerList::createGeneralMarkerLink(address_t target, Symbol *symbol,
    size_t addend, Module *module) {

    LOG(10, "    general markerLink to " << std::hex << target);
    auto list = module->getMarkerList();
    auto marker = list->findOrAddGeneralMarker(target, symbol);
    return new MarkerLink(marker, addend);
}

Link *MarkerList::createStartOrEndMarkerLink(address_t target, Symbol *symbol,
    size_t addend, DataSection *dataSection, Module *module) {

    auto list = module->getMarkerList();
    if(dataSection->getAddress() == target) {
        LOG(10, "    start markerLink to "
            << std::hex << target);
        auto marker = list->findOrAddStartMarker(symbol, dataSection);
        return new MarkerLink(marker, addend);
    }
    if(dataSection->getAddress() + dataSection->getSize() == target) {
        LOG(10, "    end markerLink to " << std::hex << target);
        auto marker = list->findOrAddEndMarker(symbol, dataSection);
        return new MarkerLink(marker, addend);
    }
    return nullptr;
}

Marker *MarkerList::findOrAddGeneralMarker(address_t target, Symbol *symbol) {
    for(auto marker : CIter::children(this)) {
        if(marker->getAddress() != target) continue;
        if(marker->getSymbol() != symbol) continue;
        return marker;
    }
    LOG(11, "     create new one");
    auto marker = new Marker(target, symbol);
    getChildren()->add(marker);
    return marker;
}

Marker *MarkerList::findOrAddStartMarker(Symbol *symbol,
    DataSection *dataSection) {

    for(auto marker : CIter::children(this)) {
        if(auto startMarker = dynamic_cast<SectionStartMarker *>(marker)) {
            if(startMarker->getDataSection() != dataSection) continue;
            if(marker->getSymbol() != symbol) continue;
            return startMarker;
        }
    }
    LOG(11, "     create new one");
    auto marker = new SectionStartMarker(dataSection, symbol);
    getChildren()->add(marker);
    return marker;
}

Marker *MarkerList::findOrAddEndMarker(Symbol *symbol,
    DataSection *dataSection) {

    for(auto marker : CIter::children(this)) {
        if(auto endMarker = dynamic_cast<SectionEndMarker *>(marker)) {
            if(endMarker->getDataSection() != dataSection) continue;
            if(marker->getSymbol() != symbol) continue;
            return endMarker;
        }
    }
    LOG(11, "     create new one");
    auto marker = new SectionEndMarker(dataSection, symbol);
    getChildren()->add(marker);
    return marker;
}

