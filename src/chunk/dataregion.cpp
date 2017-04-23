#include "dataregion.h"
#include "link.h"
#include "position.h"
#include "concrete.h"
#include "visitor.h"
#include "log/log.h"

DataRegion::DataRegion(ElfXX_Phdr *phdr) {
    this->phdr = phdr;
    setPosition(new AbsolutePosition(phdr->p_vaddr));
    setSize(phdr->p_memsz);
}

void DataRegion::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

void DataRegionList::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

Link *DataRegionList::createDataLink(address_t target, bool isRelative) {
    for(auto region : CIter::children(this)) {
        if(region->getRange().contains(target)) {
            if(isRelative) {
                return new DataOffsetLink(region, target);
            }
            else {
                return new AbsoluteDataLink(region, target);
            }
        }
    }
    return nullptr;
}

void DataRegionList::buildDataRegionList(ElfMap *elfMap, Module *module) {
    auto list = new DataRegionList();

    for(void *s : elfMap->getSegmentList()) {
        Elf64_Phdr *phdr = static_cast<Elf64_Phdr *>(s);

        DataRegion *region = nullptr;
        if(phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_W)) {
            LOG(1, "Found data region at 0x" << std::hex << phdr->p_vaddr);
            region = new DataRegion(phdr);
            list->getChildren()->add(region);
        }
        else if(phdr->p_type == PT_TLS) {
            LOG(1, "Found TLS data region at 0x" << std::hex << phdr->p_vaddr);
            auto region = new DataRegion(phdr);
            list->getChildren()->add(region);
            list->setTLS(region);
        }
    }

    module->setDataRegionList(list);
}
