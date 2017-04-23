#include "dataregion.h"
#include "link.h"
#include "position.h"
#include "concrete.h"
#include "visitor.h"
#include "log/log.h"

DataRegion::DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr) {
    this->phdr = phdr;
    setPosition(new AbsolutePosition(phdr->p_vaddr));
    setSize(phdr->p_memsz);
}

void DataRegion::updateAddressFor(address_t baseAddress) {
    LOG(1, "UPDATE address for DataRegion from " << std::hex
        << getAddress() << " to " << (baseAddress + phdr->p_vaddr));
    getPosition()->set(baseAddress + phdr->p_vaddr);
}

void DataRegion::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void DataRegionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

Link *DataRegionList::createDataLink(address_t target, bool isRelative) {
    LOG(10, "MAKE LINK to " << std::hex << target
        << ", relative? " << isRelative);
    for(auto region : CIter::children(this)) {
        if(region->getRange().contains(target)) {
            auto base = region->getAddress();
            if(isRelative) {
                return new DataOffsetLink(region, target - base);
            }
            else {
                return new AbsoluteDataLink(region, target - base);
            }
        }
    }
    LOG(1, "    unable to make link!");
    return nullptr;
}

void DataRegionList::buildDataRegionList(ElfMap *elfMap, Module *module) {
    auto list = new DataRegionList();

    for(void *s : elfMap->getSegmentList()) {
        Elf64_Phdr *phdr = static_cast<Elf64_Phdr *>(s);

        DataRegion *region = nullptr;
        if(phdr->p_type == PT_LOAD /*&& phdr->p_flags == (PF_R | PF_W)*/) {
            region = new DataRegion(elfMap, phdr);
            LOG(1, "Found data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
        }
        else if(phdr->p_type == PT_TLS) {
            auto region = new DataRegion(elfMap, phdr);
            LOG(1, "Found TLS data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
            list->setTLS(region);
        }
    }

    module->setDataRegionList(list);
}
