#include <iostream>
#include "sandbox.h"

bool Slot::append(uint8_t *data, size_t size) {
    if(size > available) return false;

    memcpy(static_cast<void *>(address), static_cast<void *>(data), size);
    address += size;
    size -= available;
    return true;
}

bool AnyLengthSlot::append(uint8_t *data, size_t size) {
    buffer.insert(buffer.end(), data, data + size);
    return true;
}

MemoryBacking::MemoryBacking(size_t size) : SandboxBacking(size) {
    base = mmap(0, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(!base) {
        throw std::bad_alloc();
    }
}

void MemoryBacking::finalize() {
    mprotect(base, size, PROT_READ | PROT_EXEC);
}

ELFBacking::ELFBacking(std::string filename)
    : MemoryBacking(MAX_SANDBOX_SIZE), filename(filename) {
    
}

void ELFBacking::finalize() {
    MemoryBacking::finalize();
    std::cerr << "Not yet implemented: write ELF data to \""
        << filename << "\"\n";
}

WatermarkSandbox::WatermarkSandbox(Allocator alloc, size_t size)
    : Sandbox(alloc), size(size) {

    watermark = base;
}

Slot WatermarkAllocator::allocate(size_t request) {
    if(watermark + request > getBase() + getSize()) {
        throw std::bad_alloc();
    }

    address_t region = watermark;
    watermark += request;
    return Slot(region, request);
}
