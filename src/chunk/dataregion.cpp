#include "dataregion.h"
#include "link.h"
#include "position.h"
#include "concrete.h"
#include "visitor.h"
#include "elf/elfspace.h"
#include "log/log.h"

address_t DataVariable::getAddress() {
    return region->getAddress() + offset;
}

DataRegion::DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr) {
    this->phdr = phdr;
    setPosition(new AbsolutePosition(phdr->p_vaddr));
    setSize(phdr->p_memsz);
}

void DataRegion::addVariable(DataVariable *variable) {
    variableList.push_back(variable);
}

bool DataRegion::contains(address_t address) {
    return getRange().contains(address);
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
    LOG(1, "    unable to make link!");
    return nullptr;
}

DataRegion *DataRegionList::findRegionContaining(address_t target) {
    for(auto region : CIter::children(this)) {
        if(region->contains(target)) {
            return region;
        }
    }
    return nullptr;
}

#if 0
bool DataRegionList::isRelocationRelative(Reloc *r) {
    switch(r->getType()) {
    case R_X86_64_GLOB_DAT:     return false;
    case R_X86_64_JUMP_SLOT:    return false;
    case R_X86_64_PLT32:        return false;
    case R_X86_64_PC32:         return true;
    case R_X86_64_64:           return false;
    case R_X86_64_RELATIVE:     return true;
    case R_X86_64_TPOFF64:      return false;  // index into tls table
    case R_X86_64_COPY:         return false;  // hmm...
    default:                    return false;
    }
}
#endif

Link *DataRegionList::resolveVariableLink(Reloc *reloc) {
#ifdef ARCH_X86_64
    // this is the only reloc type we've seen in TLS
    if(reloc->getType() == R_X86_64_RELATIVE) {
        return createDataLink(reloc->getAddend(), true);
    }
#else
    #error "relocation types NYI on aarch64!"
#endif
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

    // make variables for all relocations located inside the regions
    for(auto reloc : *module->getElfSpace()->getRelocList()) {
#if 0
        switch(reloc->getType()) {
        case R_X86_64_GLOB_DAT:
        case R_X86_64_JUMP_SLOT:
        case R_X86_64_PLT32:
        case R_X86_64_64:
            link = list->createDataLink(reloc->getAddress(), false);
            break;
        case R_X86_64_PC32:
        case R_X86_64_RELATIVE:
            // in theory variables might use relative relocations, but that
            // would normally be for jump tables (handled separately)
            break;
        case R_X86_64_TPOFF64:  // index into tls table
        case R_X86_64_COPY:
        default:
            break;
        }
#endif

        if(auto link = list->resolveVariableLink(reloc)) {
            // source region (will be different from the link's dest region)
            auto region = list->findRegionContaining(reloc->getAddress());
            if(region) {
                auto var = new DataVariable(region,
                    reloc->getAddress() - region->getAddress(), link);
                region->addVariable(var);
            }
            else delete link;
        }
    }

    module->setDataRegionList(list);
}
