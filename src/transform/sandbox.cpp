#include <iostream>
#include <cstring>
#include <sys/mman.h>
#include "sandbox.h"
#include "generate/objgen.h"

bool Slot::append(uint8_t *data, size_t size) {
    if(size > available) return false;

    std::memcpy((void *)address, (void *)data, size);
    address += size;
    size -= available;
    return true;
}

MemoryBacking::MemoryBacking(size_t size) : SandboxBacking(size) {
#if defined(ARCH_AARCH64)
    #define _ADDRESS    0x80000000
#else
    #define _ADDRESS    0x40000000
#endif
    base = (address_t) mmap((void *)_ADDRESS, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS
#ifdef ARCH_X86_64
        | MAP_32BIT
#endif
        , -1, 0);
    if(base != _ADDRESS) throw "Overlapping with other regions?";
    if(base == (address_t)-1) {
        throw std::bad_alloc();
    }
#undef _ADDRESS
}

void MemoryBacking::finalize() {
    mprotect((void *)base, getSize(), PROT_READ | PROT_EXEC);
}

ExeBacking::ExeBacking(ElfSpace *elfSpace, std::string filename)
    : MemoryBacking(MAX_SANDBOX_SIZE), elfSpace(elfSpace), filename(filename) {

}

void ExeBacking::finalize() {
    MemoryBacking::finalize();
#if 0
    ExeGen *gen = new ExeGen(elfSpace, this, filename);
    gen->generate();
    delete gen;
#endif
}

ObjBacking::ObjBacking(ElfSpace *elfSpace, std::string filename)
    : MemoryBacking(MAX_SANDBOX_SIZE), elfSpace(elfSpace), filename(filename) {

}

void ObjBacking::finalize() {
    MemoryBacking::finalize();
    ObjGen *gen = new ObjGen(elfSpace, this, filename);
    gen->generate();
    delete gen;
}
