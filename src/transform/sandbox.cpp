#include <iostream>
#include <cstring>
#include <sys/mman.h>
#include "sandbox.h"
#include "generate/objgen.h"
#include "generate/anygen.h"
#include "chunk/module.h"
#include "config.h"

bool Slot::append(uint8_t *data, size_t size) {
    if(size > available) return false;

    std::memcpy((void *)address, (void *)data, size);
    address += size;
    size -= available;
    return true;
}

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

bool MemoryBacking::recreate() {
    std::memset((void *)base, 0, getSize());
    return 0;
}

ExeBacking::ExeBacking(ElfSpace *elfSpace, std::string filename)
    : MemoryBacking(SANDBOX_BASE_ADDRESS, MAX_SANDBOX_SIZE),
    elfSpace(elfSpace), filename(filename) {

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
    : MemoryBacking(SANDBOX_BASE_ADDRESS, MAX_SANDBOX_SIZE),
    elfSpace(elfSpace), filename(filename) {

}

void ObjBacking::finalize() {
    MemoryBacking::finalize();
    ObjGen *gen = new ObjGen(elfSpace, this, filename);
    gen->generate();
    delete gen;
}

AnyGenerateBacking::AnyGenerateBacking(Module *module, std::string filename)
    : MemoryBacking(SANDBOX_BASE_ADDRESS, MAX_SANDBOX_SIZE),
    module(module), filename(filename) {

}

void AnyGenerateBacking::finalize() {
    MemoryBacking::finalize();
    AnyGen *gen = new AnyGen(module, this);
    gen->generate(filename);
    delete gen;
}
