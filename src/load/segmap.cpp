#include <iostream>

#include <sys/mman.h>
#include <elf.h>

#include "segmap.h"

#define ROUND_DOWN(x)   ((x) & ~0xfff)
#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

void SegMap::mapSegments(ElfMap &elf, address_t baseAddress) {
    auto segmentList = elf.getSegmentList();
    for(void *s : segmentList) {
        Elf64_Phdr *phdr = static_cast<Elf64_Phdr *>(s);
        if(phdr->p_type != PT_LOAD) continue;

        mapElfSegment(elf, phdr, baseAddress);
    }
}

void SegMap::mapElfSegment(ElfMap &elf, Elf64_Phdr *phdr,
    address_t baseAddress) {

    int prot = 0;
    if(phdr->p_flags & PF_R) prot |= PROT_READ;
    if(phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if(phdr->p_flags & PF_X) prot |= PROT_EXEC;

    size_t address = ROUND_DOWN(phdr->p_vaddr);
    size_t address_offset = phdr->p_vaddr - address;
    size_t offset = ROUND_DOWN(phdr->p_offset);

    size_t memsz_pages  = ROUND_UP(phdr->p_memsz + address_offset);
    size_t filesz_pages = ROUND_UP(phdr->p_filesz + address_offset);

    address += baseAddress;  // relocate shared code by the given offset

    void *mem = 0;
    if(memsz_pages > filesz_pages) {
        mem = mmap((void *)address,
            memsz_pages,
            prot,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
            -1, 0);
        munmap(mem, filesz_pages);
        mem = mmap(mem, filesz_pages, prot,
            MAP_PRIVATE | MAP_FIXED,
            elf.getFileDescriptor(),
            offset);
        if(mem == (void *)-1) throw "Out of memory?";
    }
    else {  // no extra zero pages
        mem = mmap((void *)address,
            memsz_pages,
            prot,
            MAP_PRIVATE | MAP_FIXED,
            elf.getFileDescriptor(),
            offset);
        if(mem == (void *)-1) throw "Out of memory?";
    }

    std::cout << "mapped file offset " << std::hex << phdr->p_offset
        << " (virtual address " << std::hex << phdr->p_vaddr << ")"
        << " to " << std::hex << mem << std::endl;
}
