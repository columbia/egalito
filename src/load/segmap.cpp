#include <iostream>
#include <fstream>
#include <cstring>  // for std::memset

#include <sys/mman.h>
#include <elf.h>

#include "segmap.h"
#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "pass/clearspatial.h"
#include "transform/data.h"
#include "log/log.h"
#include "log/temp.h"

#define ROUND_DOWN(x)   ((x) & ~0xfff)
#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

void SegMap::mapAllSegments(ConductorSetup *setup) {
    auto elf = setup->getElfMap();
    auto egalito = setup->getEgalitoElfMap();

#if 0
    // map PT_LOAD sections into memory
    if(elf) {
        SegMap::mapSegments(*elf, elf->getBaseAddress());
    }
    if(egalito) {
        SegMap::mapSegments(*egalito, egalito->getBaseAddress());
    }

    ClearSpatialPass clearSpatial;
    for(auto module : CIter::modules(setup->getConductor()->getProgram())) {
#if 0
        auto map = module->getElfSpace()->getElfMap();
        if(map && map != elf && map != egalito) {
            SegMap::mapSegments(*map, map->getBaseAddress());
        }
#else
        for(auto region : CIter::regions(module)) {
            mapRegion(region);
        }
#endif
    }
#else
    for(auto module : CIter::modules(setup->getConductor()->getProgram())) {
        for(auto region : CIter::regions(module)) {
            mapRegion(region);
        }
    }
    ClearSpatialPass clearSpatial;
#endif
    for(auto module : CIter::modules(setup->getConductor()->getProgram())) {
        for(auto region : CIter::regions(module)) {
            //DataLoader(0).loadRegion(nullptr, region);
            region->accept(&clearSpatial);
        }
    }
}

void SegMap::mapSegments(ElfMap &elf, address_t baseAddress) {
    auto segmentList = elf.getSegmentList();
    try {
        for(void *s : segmentList) {
            Elf64_Phdr *phdr = static_cast<Elf64_Phdr *>(s);
            if(phdr->p_type != PT_LOAD) continue;

            mapElfSegment(elf, phdr, baseAddress);
        }
    }
    catch (const char *s) {
        TemporaryLogLevel tll("load", 1);
        LOG(1, s);

        std::ifstream ms("/proc/self/maps");
        LOG(1, ms.rdbuf());

        std::cout.flush();
    }
}

void SegMap::mapElfSegment(ElfMap &elf, Elf64_Phdr *phdr,
    address_t baseAddress) {

    int prot = 0;
    if(phdr->p_flags & PF_R) prot |= PROT_READ;
    if(phdr->p_flags & PF_W) prot |= PROT_WRITE;
    //if(phdr->p_flags & PF_X) prot |= PROT_EXEC;

    prot |= PROT_WRITE;  // !!! hack for updating jump tables

    size_t address = ROUND_DOWN(phdr->p_vaddr);
    size_t address_offset = phdr->p_vaddr - address;
    size_t offset = ROUND_DOWN(phdr->p_offset);

    size_t memsz_pages  = ROUND_UP(phdr->p_memsz + address_offset);
    size_t filesz_pages = ROUND_UP(phdr->p_filesz + address_offset);
    size_t filesz_orig  = phdr->p_filesz + address_offset;

    address += baseAddress;  // relocate shared code by the given offset

    // sometimes, with -Wl,-q, the linker generates empty data LOAD sections
    if(memsz_pages == 0) return;

    LOG(1, "mapping file offset " << std::hex << phdr->p_offset
        << " (virtual address " << std::hex << phdr->p_vaddr
        << ") at " << std::hex << address << " size " << memsz_pages);

    void *mem = 0;
    if(memsz_pages > filesz_pages) {
        // first map the full pages including zero pages, unmap and remap
        mem = mmap((void *)address,
            memsz_pages,
            prot,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1, 0);
        if(mem == (void *)-1) throw "Out of memory?";
        if(mem != (void *)address) {
            LOG(1, "1) mapped to " << std::hex << mem
                << " instead of " << address);
            throw "Overlapping with other regions?";
        }
        if(filesz_pages > 0) {
            munmap(mem, filesz_pages);
            mem = mmap(mem, filesz_pages, prot,
                MAP_PRIVATE,
                elf.getFileDescriptor(),
                offset);
            // the last page from the file might need zeroing, in case
            // we mapped too much data in by rounding up to a page
            if(filesz_orig != filesz_pages) {
                std::memset(static_cast<char *>(mem) + filesz_orig,
                    0, filesz_pages - filesz_orig);
            }
            if(mem == (void *)-1) throw "Out of memory?";
            if(mem != (void *)address) {
                LOG(1, "2) mapped to " << std::hex << mem
                    << " instead of " << address);
                throw "Overlapping with other regions?";
            }
        }
    }
    else {
        // in this case there are no extra zero pages
        mem = mmap((void *)address,
            memsz_pages,
            prot,
            MAP_PRIVATE,
            elf.getFileDescriptor(),
            offset);
        if(mem == (void *)-1) throw "Out of memory?";
        if(mem != (void *)address) {
            LOG(1, "3) mapped to " << std::hex << mem
                << " instead of " << address);
            throw "Overlapping with other regions?";
        }
        if(filesz_orig != filesz_pages) {
            std::memset(static_cast<char *>(mem) + filesz_orig,
                0, filesz_pages - filesz_orig);
        }
    }
}

void SegMap::mapRegion(DataRegion *region) {
    int prot = 0;
    if(region->readable()) prot |= PROT_READ;
    if(region->writable()) prot |= PROT_WRITE;
    // disable exec for now, only Sandbox should contain code
    //if(region->executable()) prot |= PROT_EXEC;

    prot |= PROT_WRITE;  // !!! hack for updating jump tables. And for memcpy below

    address_t address = region->getAddress();
    address_t address_rounded = ROUND_DOWN(address);
    size_t address_offset = address - address_rounded;
    size_t memsz_pages = ROUND_UP(region->getSize() + address_offset);

    LOG(1, "mmap " << std::hex << address_rounded << " pages=" << memsz_pages);

    // map enough pages for all data (including zero pages)
    void *mem = mmap((void *)address_rounded,
        memsz_pages,
        prot,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1, 0);
    if(mem == nullptr) throw "mmap DataRegion returned NULL!";
    const std::string &dataBytes = region->getDataBytes();
    LOG(1, "memcpy " << std::hex << (void *)dataBytes.c_str() << " to " << address
        << " size " << dataBytes.length());
    std::memcpy((void *)address, dataBytes.c_str(), dataBytes.length());
}
