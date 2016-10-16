#include <iostream>
#include <cstring>
#include <sys/mman.h>
#include "sandbox.h"
#include "elf/elfgen.h"

bool Slot::append(uint8_t *data, size_t size) {
    if(size > available) return false;

    std::memcpy((void *)address, (void *)data, size);
    address += size;
    size -= available;
    return true;
}

bool AnyLengthSlot::append(uint8_t *data, size_t size) {
    buffer.insert(buffer.end(), data, data + size);
    return true;
}

MemoryBacking::MemoryBacking(size_t size) : SandboxBacking(size) {
    base = (address_t) mmap(0, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if(!base) {
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
