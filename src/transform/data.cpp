#include <cstring>  // for memcpy, memset
#include <sys/mman.h>
#include <fstream>
#include "data.h"
#include "chunk/tls.h"
#include "../dep/rtld/pthread.h"
#include "../dep/rtld/tcbhead.h"
#include "elf/elfspace.h"
#include "log/log.h"
#include "log/temp.h"

#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

address_t DataLoader::allocateTLS(size_t size, size_t *offset) {
#ifdef ARCH_X86_64
    // header is at the end
    address_t tp = tlsBaseAddress + size;
    size += sizeof(struct my_tcbhead_t);  // add space for header
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
    // header is at the beginning
    address_t tp = tlsBaseAddress + sizeof(struct my_pthread);
    if(offset) *offset += sizeof(struct my_pthread);
#endif

    if(size > 0) {
        LOG(1, "mapping TLS region into memory at 0x"
            << std::hex << tlsBaseAddress << ", size 0x" << size);
        void *mem = mmap((void *)tlsBaseAddress,
            ROUND_UP(size),
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1, 0);
        if(mem == (void *)-1) throw "Out of memory?";
        if(mem != (void *)tlsBaseAddress) {
            TemporaryLogLevel tll("transform", 1);
            LOG(1, "allocateTLS failed");
            std::ifstream ms("/proc/self/maps");
            LOG(1, ms.rdbuf());

            std::cout.flush();
            throw "Overlapping with other regions?";
        }
    }

    return tp;
}

void DataLoader::loadRegion(ElfMap *elfMap, DataRegion *region) {
#if 0
    auto phdr = region->getPhdr();
    address_t sourceAddr = elfMap->getBaseAddress() + phdr->p_vaddr;
    char *source = reinterpret_cast<char *>(sourceAddr);
    char *output = reinterpret_cast<char *>(region->getAddress());
    LOG(1, "copying " << region->getName() << ": " << (void *)source
        << " -> " << (void *)output << " + " << phdr->p_filesz);
    std::memcpy(output, source, phdr->p_filesz);
    LOG(1, "    clearing " << (void *)(output + phdr->p_filesz)
        << " + " << (phdr->p_memsz - phdr->p_filesz));
    std::memset(output + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);
#else
    const std::string &source = region->getDataBytes();
    char *output = reinterpret_cast<char *>(region->getAddress());

    LOG(1, "loading DataRegion " << region->getName()
        << " at 0x" << std::hex << region->getAddress());

    std::memcpy(output, source.c_str(), source.length());
    size_t zeroBytes = region->getSize() - source.length();
    std::memset(output + source.length(), 0, zeroBytes);
#endif
}
