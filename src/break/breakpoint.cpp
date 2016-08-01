#include <iostream>
#include <sys/mman.h>
#include "breakpoint.h"

static void aligned_mprotect(unsigned long dest, unsigned long size, int protection) {
    unsigned long dest_page = dest & ~0xFFF;
    unsigned long bytes_rounded = ((dest + size + 0xFFF) & ~0xFFF) - dest_page;
    mprotect((void *)dest_page, bytes_rounded, protection);
}

Breakpoint::Breakpoint(address_t address) : address(address) {
    char *p = reinterpret_cast<char *>(address);

    aligned_mprotect(address, 1, PROT_READ | PROT_WRITE);
    originalData = *p;
    *p = 0xf4;
    aligned_mprotect(address, 1, PROT_READ | PROT_EXEC);
}

Breakpoint *BreakpointManager::set(address_t address) {
    std::cout << "SETTING BREAKPOINT at " << address << std::endl;
    Breakpoint *b = new Breakpoint(address);

    list.push_back(b);
    return b;
}
