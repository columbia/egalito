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
    : SandboxBacking(size) {

    base = (address_t) mmap((void *)address, size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS
#ifdef ARCH_X86_64
        | MAP_32BIT
#endif
        , -1, 0);
    if(base == (address_t)-1) {
        throw std::bad_alloc();
    }
    if(base != address) throw "Sandbox: Overlapping with other regions?";
}

void MemoryBacking::finalize() {
    mprotect((void *)base, getSize(), PROT_READ | PROT_EXEC);
}

bool MemoryBacking::reopen() {
    mprotect((void *)base, getSize(), PROT_READ | PROT_WRITE);
    return true;
}

void MemoryBacking::recreate(address_t end) {
    std::memset((void *)base, 0, end - base);
}

MemoryBufferBacking::MemoryBufferBacking(address_t address, size_t size)
    : SandboxBacking(size), base(address) {

}

void MemoryBufferBacking::finalize() {
    // nothing to do
}

bool MemoryBufferBacking::reopen() {
    // nothing to do
    return true;
}

bool MemoryBufferBacking::recreate() {
    buffer.clear();
    return false;
}
