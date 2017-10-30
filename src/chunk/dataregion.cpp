#include <iomanip>
#include "dataregion.h"
#include "link.h"
#include "position.h"
#include "concrete.h"
#include "visitor.h"
#include "chunk/aliasmap.h"
#include "chunk/dump.h"
#include "elf/elfspace.h"
#include "operation/find.h"
#include "operation/mutator.h"
#include "util/streamasstring.h"
#include "log/log.h"
#include "log/temp.h"

DataSection::DataSection(ElfMap *elfMap, ElfXX_Phdr *phdr, ElfXX_Shdr *shdr)
    : size(shdr->sh_size), align(shdr->sh_addralign),
      code(shdr->sh_flags & SHF_EXECINSTR), bss(shdr->sh_type == SHT_NOBITS),
      name(elfMap->getSHStrtab() + shdr->sh_name) {

    address_t offset = shdr->sh_addr - phdr->p_vaddr;
    this->setPosition(new AbsoluteOffsetPosition(this, offset));
    originalOffset = offset;
}

std::string DataSection::getName() const {
    return name;
}

bool DataSection::contains(address_t address) {
    return getRange().contains(address);
}

DataVariable::DataVariable(DataRegion *region, address_t address, Link *dest)
    : dest(dest) {

    auto section = CIter::spatial(region)->findContaining(address);
    if(!section) {
        LOG(10, "in " << region->getName() << ", address " << address);
        ChunkDumper dumper;
        region->accept(&dumper);
        throw "no section contains this variable!";
    }

    auto offset = address - section->getAddress();
    this->setPosition(new AbsoluteOffsetPosition(this, offset));
    ChunkMutator(section).append(this);
}

DataRegion::DataRegion(ElfMap *elfMap, ElfXX_Phdr *phdr) {
    this->phdr = phdr;
    setPosition(new AbsolutePosition(phdr->p_vaddr));
    setSize(phdr->p_memsz);
    originalAddress = getAddress();
    startOffset = 0;
    mappedAddress = 0;
    if(!writable()) {
        if(auto sec = elfMap->findSection(".rodata")) {
            startOffset = sec->getVirtualAddress() - getOriginalAddress();
        }
        else {
            startOffset = getSize();
        }
    }
}

std::string DataRegion::getName() const {
    StreamAsString stream;
    stream << "region-0x" << std::hex << originalAddress;
    return stream;
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
    mappedAddress = baseAddress + phdr->p_vaddr;
}

DataVariable *DataRegion::findVariable(address_t address) const {
    for(auto var : variableList) {
        if(var->getAddress() == address) {
            return var;
        }
    }
    return nullptr;
}

DataSection *DataRegion::findDataSectionContaining(address_t address) {
    for(auto ds : CIter::children(this)) {
        if(ds->contains(address)) {
            return ds;
        }
    }
    return nullptr;
}

void DataRegion::accept(ChunkVisitor *visitor) {
    visitor->visit(this);
}

std::string TLSDataRegion::getName() const {
    return "region-TLS";
}

void TLSDataRegion::setBaseAddress(address_t baseAddress) {
    LOG(1, "set base address for TLSDataRegion from " << std::hex
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

Link *DataRegionList::createDataLink(address_t target, Module *module,
    bool isRelative) {

    LOG(10, "MAKE LINK to " << std::hex << target
        << ", relative? " << isRelative);

    for(auto region : CIter::children(this)) {
        if(region->contains(target)) {
            auto dsec = CIter::spatial(region)->findContaining(target);
            if(dsec) {
                if(dsec->isCode()) {
                    if(ChunkFind().findInnermostAt(
                        module->getFunctionList(), target)) {

                        LOG(1, "is this a hand-crafted jump table? " << target);
                        return nullptr;
                    }
                    else {
                        // this will very likely to result in a too-far
                        // link for AARCH64.
                        LOG(9, "is this a LITERAL? " << target);
                        return nullptr;
                    }
                }
                auto base = dsec->getAddress();
                LOG(10, "" << target << " has offset " << (target - base));
                if(isRelative) {
                    return new DataOffsetLink(dsec, target - base);
                }
                else {
                    return new AbsoluteDataLink(dsec, target - base);
                }
            }
        }
    }

    return nullptr;
}

DataRegion *DataRegionList::findRegionContaining(address_t target) {
    // check for TLS region first, since it will overlap another LOAD segment
    if(tls && tls->containsData(target)) return tls;

    return findNonTLSRegionContaining(target);
}

DataRegion *DataRegionList::findNonTLSRegionContaining(address_t target) {
    for(auto region : CIter::children(this)) {
        if(region == tls) continue;

        if(region->contains(target)) {
            return region;
        }
    }
    return nullptr;
}

void DataRegionList::buildDataRegionList(ElfMap *elfMap, Module *module) {
    auto list = new DataRegionList();

    for(void *s : elfMap->getSegmentList()) {
        ElfXX_Phdr *phdr = static_cast<ElfXX_Phdr *>(s);

        if(phdr->p_type == PT_LOAD /*&& phdr->p_flags == (PF_R | PF_W)*/) {
            auto region = new DataRegion(elfMap, phdr);
            LOG(9, "Found data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
        }
        else if(phdr->p_type == PT_TLS) {
            auto region = new TLSDataRegion(elfMap, phdr);
            LOG(9, "Found TLS data region at 0x"
                << std::hex << region->getAddress()
                << " size 0x" << region->getSize());
            list->getChildren()->add(region);
            list->setTLS(region);
        }
    }

    for(auto v : elfMap->findSectionsByFlag(SHF_ALLOC)) {
        auto shdr = static_cast<ElfXX_Shdr *>(v);
        DataRegion *region = nullptr;
        if(shdr->sh_flags & SHF_TLS) {
            region = list->getTLS();
        }
        else {
            region = list->findNonTLSRegionContaining(shdr->sh_addr);
        }
        auto ds = new DataSection(elfMap, region->getPhdr(), shdr);
        ChunkMutator(region).append(ds);
    }

    module->setDataRegionList(list);
    IF_LOG(10) {
        ChunkDumper dumper;
        for(auto region : CIter::regions(module)) {
            region->accept(&dumper);
        }
    }

    module->setMarkerList(new MarkerList());
}
