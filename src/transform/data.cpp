#include <cstring>  // for memcpy, memset
#include <assert.h>
#include <sys/mman.h>
#include <fstream>
#include "data.h"
#include "chunk/tls.h"
#include "chunk/dataregion.h"
#ifdef USE_LOADER
    #include "../dep/rtld/pthread.h"
    #include "../dep/rtld/tcbhead.h"
#endif
#include "exefile/exefile.h"
#include "log/log.h"
#include "log/temp.h"

#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)
#define ROUND_UP_BY(x, y)   (((x) + (y) - 1) & ~((y) - 1))

#ifdef USE_LOADER
address_t DataLoader::allocateTLS(address_t base, size_t size, size_t *offset) {
#ifdef ARCH_X86_64
    // header is at the end
    size = ROUND_UP_BY(size, 64);
    address_t tp = base + size;
    //size += sizeof(struct my_tcbhead_t);  // add space for header
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    // header is at the beginning
    address_t tp = base + sizeof(struct my_pthread);
    *offset += sizeof(struct my_pthread);
#elif defined(ARCH_RISCV)
    address_t tp;
    assert(0); // XXX: no idea yet
#endif
    size += sizeof(struct my_pthread);

    if(size > 0) {
        LOG(1, "mapping TLS region into memory at 0x"
            << std::hex << base << ", size 0x" << size);
        void *mem = mmap((void *)base,
            ROUND_UP(size),
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1, 0);
        if(mem == (void *)-1) throw "Out of memory?";
        if(mem != (void *)base) {
            TemporaryLogLevel tll("transform", 1);
            LOG(1, "allocateTLS failed");
            std::ifstream ms("/proc/self/maps");
            LOG(1, ms.rdbuf());

            std::cout.flush();
            throw "TLS: Overlapping with other regions?";
        }
    }

    return tp;
}
#endif

void DataLoader::loadRegion(DataRegion *region) {
    const std::string &source = region->getDataBytes();
    char *output = reinterpret_cast<char *>(region->getAddress());

    LOG(1, "loading DataRegion " << region->getName()
        << " at 0x" << std::hex << region->getAddress());

    std::memcpy(output, source.c_str(), source.length());
    size_t zeroBytes = region->getSize() - source.length();
    std::memset(output + source.length(), 0, zeroBytes);
}

address_t DataLoader::loadRegionTo(address_t address, DataRegion *region) {
    const std::string &source = region->getDataBytes();
    char *output = reinterpret_cast<char *>(address);
    std::memcpy(output, source.c_str(), source.length());
    size_t zeroBytes = region->getSize() - source.length();
    std::memset(output + source.length(), 0, zeroBytes);
    return address + region->getSize();
}
