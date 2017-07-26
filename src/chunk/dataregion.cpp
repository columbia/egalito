#include <iomanip>
#include "dataregion.h"
#include "link.h"
#include "position.h"
#include "concrete.h"
#include "visitor.h"
#include "elf/elfspace.h"
#include "util/streamasstring.h"
#include "log/log.h"

std::string DataRegion::getName() const {
    StreamAsString stream;
    stream << "region-0x" << std::hex << originalAddress;
    return stream;
}

address_t DataVariable::getAddress() {
    return region->getAddress() + offset;
}

DataRegion::DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr) {
    this->phdr = phdr;
    setPosition(new AbsolutePosition(phdr->p_vaddr));
    setSize(phdr->p_memsz);
    originalAddress = getAddress();
}

void DataRegion::addVariable(DataVariable *variable) {
    variableList.push_back(variable);
}

bool DataRegion::contains(address_t address) {
    return getRange().contains(address);
}

bool DataRegion::endsWith(address_t address) {
    return getRange().endsWith(address);
}

void DataRegion::updateAddressFor(address_t baseAddress) {
    LOG(1, "UPDATE address for DataRegion from " << std::hex
        << getAddress() << " to " << (baseAddress + phdr->p_vaddr));
    getPosition()->set(baseAddress + phdr->p_vaddr);
}

void DataRegion::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

std::string TLSDataRegion::getName() const {
    return "region-TLS";
}

void TLSDataRegion::updateAddressFor(address_t baseAddress) {
    LOG(1, "UPDATE address for TLSDataRegion from " << std::hex
        << getAddress() << " to " << baseAddress);
    getPosition()->set(baseAddress);
}

bool TLSDataRegion::containsData(address_t address) {
    auto phdr = getPhdr();
    return Range(getAddress(), phdr->p_filesz).contains(address);
}

void DataRegionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

Link *DataRegionList::createDataLink(address_t target, bool isRelative) {
    LOG(10, "MAKE LINK to " << std::hex << target
        << ", relative? " << isRelative);
    for(auto region : CIter::children(this)) {
        if(region->contains(target)) {
            auto base = region->getAddress();
            if(isRelative) {
                return new DataOffsetLink(region, target - base);
            }
            else {
                return new AbsoluteDataLink(region, target - base);
            }
        }
    }
    /* this case occurs when a pointer is pointing to the next address of a
     * data region, e.g. a label _end points to the next address of _bss */
    for(auto region : CIter::children(this)) {
        if(region->endsWith(target)) {
            auto base = region->getAddress();
            if(isRelative) {
                return new DataOffsetLink(region, target - base);
            }
            else {
                return new AbsoluteDataLink(region, target - base);
            }
        }
    }
    LOG(1, "    unable to make link! (to 0x" << std::hex << target << ")");
    return nullptr;
}

DataRegion *DataRegionList::findRegionContaining(address_t target) {
    // check for TLS region first, since it will overlap another LOAD segment
    if(tls && tls->containsData(target)) return tls;

    for(auto region : CIter::children(this)) {
        if(region == tls) continue;

        if(region->contains(target)) {
            return region;
        }
    }
    return nullptr;
}

Link *DataRegionList::resolveVariableLink(Reloc *reloc, Module *module) {
#ifdef ARCH_X86_64
    // this is the only reloc type we've seen in TLS
    if(reloc->getType() == R_X86_64_RELATIVE) {
        return createDataLink(reloc->getAddend(), true);
    }
#else
#if defined(R_AARCH64_TLS_TPREL64) && !defined(R_AARCH64_TLS_TPREL)
    #define R_AARCH64_TLS_TPREL R_AARCH64_TLS_TPREL64
#endif
    if(reloc->getType() == R_AARCH64_RELATIVE) {
        if(auto f = CIter::spatial(module->getFunctionList())->findContaining(
            reloc->getAddend())) {

            return new NormalLink(f);
        }
        else {
            return createDataLink(reloc->getAddend(), true);
        }
    }

    // We can't resolve the address yet, because a link may point to a TLS
    // in another module e.g. errno referred from libm (tls can be nullptr)
    if(reloc->getType() == R_AARCH64_TLS_TPREL) {
        return new TLSDataOffsetLink(
            getTLS(), reloc->getSymbol(), reloc->getAddend());
    }
#endif
    return nullptr;
}

void DataRegionList::buildDataRegionList(ElfMap *elfMap, Module *module) {
    auto list = new DataRegionList();

    for(void *s : elfMap->getSegmentList()) {
        ElfXX_Phdr *phdr = static_cast<ElfXX_Phdr *>(s);

        if(phdr->p_type == PT_LOAD /*&& phdr->p_flags == (PF_R | PF_W)*/) {
            auto region = new DataRegion(elfMap, phdr);
            LOG(1, "Found data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
        }
        else if(phdr->p_type == PT_TLS) {
            auto region = new TLSDataRegion(elfMap, phdr);
            LOG(1, "Found TLS data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
            list->setTLS(region);
        }
    }

    // make variables for all relocations located inside the regions
    for(auto reloc : *module->getElfSpace()->getRelocList()) {
        // source region (will be different from the link's dest region)
        auto sourceRegion = list->findRegionContaining(reloc->getAddress());
        if(sourceRegion) {
            if(auto link = list->resolveVariableLink(reloc, module)) {
                LOG(10, "resolving a variable at " << std::hex
                    << reloc->getAddress()
                    << " => " << reloc->getAddend());
                if(sourceRegion == list->getTLS()) LOG(11, "from TLS!");
                auto var = new DataVariable(sourceRegion,
                    reloc->getAddress() - sourceRegion->getAddress(), link);
                sourceRegion->addVariable(var);
            }
        }
    }

    module->setDataRegionList(list);
}
