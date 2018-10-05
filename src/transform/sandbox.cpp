#include <iostream>
#include <cstring>
#include <sys/mman.h>
#include "sandbox.h"
#include "generate/objgen.h"
#include "generate/anygen.h"
#include "generate/staticgen.h"
#include "chunk/module.h"
#include "config.h"

MemoryBacking::MemoryBacking(address_t address, size_t size)
    : SandboxBackingImpl(address, size) {

    address_t base = (address_t) mmap((void *)address, size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS
#ifdef ARCH_X86_64
        | MAP_32BIT
#endif
        , -1, 0);
    if(base == (address_t)-1) {
        throw std::bad_alloc();
    }
    if(base != address) throw "Sandbox: Overlapping with other regions?";
    setBase(base);
}

void MemoryBacking::finalize() {
    mprotect((void *)getBase(), getSize(), PROT_READ | PROT_EXEC);
}

bool MemoryBacking::reopen() {
    mprotect((void *)getBase(), getSize(), PROT_READ | PROT_WRITE);
    return true;
}

void MemoryBacking::recreate() {
    std::memset((void *)getBase(), 0, getSize());
}

MemoryBufferBacking::MemoryBufferBacking(address_t address, size_t size)
    : SandboxBackingImpl(address, size) {

}

void MemoryBufferBacking::finalize() {
    // nothing to do
}

bool MemoryBufferBacking::reopen() {
    // nothing to do
    return true;
}

void MemoryBufferBacking::recreate() {
    buffer.clear();
}
