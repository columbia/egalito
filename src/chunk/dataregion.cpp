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

DataSection::DataSection(ElfXX_Phdr *phdr, ElfXX_Shdr *shdr)
    : size(shdr->sh_size), align(shdr->sh_addralign),
      bss(shdr->sh_type == SHT_NOBITS) {

    address_t offset = shdr->sh_addr - phdr->p_vaddr;
    this->setPosition(new AbsoluteOffsetPosition(this, offset));
    originalOffset = offset;
}

std::string DataSection::getName() const {
    StreamAsString stream;
    stream << "section-+0x" << std::hex << originalOffset;
    return stream;
}

bool DataSection::contains(address_t address) {
    return getRange().contains(address);
}

std::string DataRegion::getName() const {
    StreamAsString stream;
    stream << "region-0x" << std::hex << originalAddress;
    return stream;
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
            auto dsec = CIter::spatial(region)->findContaining(target);
            if(dsec) {
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

#ifdef ARCH_X86_64
    LOG(1, "    unable to make link! (to 0x" << std::hex << target << ")");
    return nullptr;
#else
    LOG(1, "    possibly defined in the linker script: " << std::hex << target);
    return new UnresolvedLink(target);
#endif
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

Link *DataRegionList::resolveVariableLink(Reloc *reloc, Module *module) {
#ifdef ARCH_X86_64
    // this is the only reloc type we've seen in TLS
    if(reloc->getType() == R_X86_64_RELATIVE) {
        return createDataLink(reloc->getAddend(), true);
    }
    return nullptr;
#else
    // We can't resolve the address yet, because a link may point to a TLS
    // in another module e.g. errno referred from libm (tls can be nullptr)
#if defined(R_AARCH64_TLS_TPREL64) && !defined(R_AARCH64_TLS_TPREL)
    #define R_AARCH64_TLS_TPREL R_AARCH64_TLS_TPREL64
#endif
    Symbol *symbol = reloc->getSymbol();
    if(reloc->getType() == R_AARCH64_TLS_TPREL
        || reloc->getType() == R_AARCH64_TLSDESC) {

        auto tls = getTLS();
        if(symbol && symbol->getSectionIndex() == 0) {
            tls = nullptr;
        }
        return new TLSDataOffsetLink(
            tls, reloc->getSymbol(), reloc->getAddend());
    }

    auto addr = reloc->getAddend();
    if(symbol) {
        addr += symbol->getAddress();
        if(symbol->getSectionIndex() == 0) {
            LOG(10, "relocation target for " << reloc->getAddress()
                << " points to an external module");
            return nullptr;
        }
    }

    return resolveInternally(addr, module);
#endif
}

Link *DataRegionList::resolveInternally(address_t address, Module *module) {
    auto func = CIter::spatial(module->getFunctionList())
        ->findContaining(address);
    if(func) {
        if(func->getAddress() == address) {
            return new NormalLink(func);
        }
        else {
            Chunk *inner = ChunkFind().findInnermostInsideInstruction(
                func, address);
            auto instruction = dynamic_cast<Instruction *>(inner);
            return new NormalLink(instruction);
        }
    }

    address += module->getElfSpace()->getElfMap()->getBaseAddress();
    return createDataLink(address, true);
}

void DataRegionList::buildDataRegionList(ElfMap *elfMap, Module *module) {
    //TemporaryLogLevel tll("chunk", 10);
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
        if(shdr->sh_flags & SHF_EXECINSTR) continue;
        DataRegion *region = nullptr;
        if(shdr->sh_flags & SHF_TLS) {
            region = list->getTLS();
        }
        else {
            region = list->findNonTLSRegionContaining(shdr->sh_addr);
        }
        LOG(10, "sh_addr " << shdr->sh_addr);
        auto ds = new DataSection(region->getPhdr(), shdr);
        ChunkMutator(region).append(ds);
    }

    // make variables for all relocations located inside the regions
    for(auto reloc : *module->getElfSpace()->getRelocList()) {
        // source region (will be different from the link's dest region)
        auto sourceRegion = list->findRegionContaining(reloc->getAddress());
        if(sourceRegion) {
#ifdef ARCH_AARCH64
            if(!sourceRegion->findDataSectionContaining(reloc->getAddress())) {
                continue;
            }
#endif
            if(auto link = list->resolveVariableLink(reloc, module)) {
                auto addr = reloc->getAddress();
                LOG0(10, "resolving a variable at " << std::hex << addr);
                if(auto sym = reloc->getSymbol()) {
                    LOG(10, " => " << sym->getName()
                        << " + " << reloc->getAddend());
                }
                else LOG(10, " no symbol");  // must resolve by address here
                if(sourceRegion == list->getTLS()) LOG(11, "from TLS!");
                auto var = new DataVariable(sourceRegion, addr, link);
                sourceRegion->addVariable(var);
            }
        }
    }

    module->setDataRegionList(list);
}

DataSection *DataRegion::findDataSectionContaining(address_t address) {
    for(auto ds : CIter::children(this)) {
        if(ds->contains(address)) {
            return ds;
        }
    }
    return nullptr;
}
