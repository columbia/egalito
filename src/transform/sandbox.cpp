#include <iostream>
#include <cstring>
#include <sys/mman.h>
#include "sandbox.h"
#include "generate/elfgen.h"

bool Slot::append(uint8_t *data, size_t size) {
    if(size > available) return false;

    std::memcpy((void *)address, (void *)data, size);
    address += size;
    size -= available;
    return true;
}

MemoryBacking::MemoryBacking(size_t size) : SandboxBacking(size) {
    base = (address_t) mmap((void *)0x40000000, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS
#ifdef ARCH_X86_64
        | MAP_32BIT
#endif
        , -1, 0);
    if(base == (address_t)-1) {
        throw std::bad_alloc();
    }
}

void MemoryBacking::finalize() {
    mprotect((void *)base, getSize(), PROT_READ | PROT_EXEC);
}

ElfBacking::ElfBacking(ElfSpace *elfSpace, std::string filename)
    : MemoryBacking(MAX_SANDBOX_SIZE), elfSpace(elfSpace), filename(filename) {

}

void ElfBacking::finalize() {
    MemoryBacking::finalize();
    ElfGen *gen = new ElfGen(elfSpace, this, filename);
    gen->generate();
}
