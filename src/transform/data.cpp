#include <cstring>  // for memcpy, memset
#include <sys/mman.h>
#include "data.h"
#include "chunk/tls.h"
#include "dep/rtld/pthread.h"
#include "elf/elfspace.h"
#include "log/log.h"

#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

#if 0
void *DataLoader::setupMainData(Module *module, address_t baseAddress) {
    size_t size = sizeof(struct my_pthread); // tcbhead_t not implemented yet
    auto tlsList = module->getTLSList();
    if(tlsList) {
        for(auto tls : *tlsList) {
            size += tls->getSize();
        }
    }
    void *mem = mmap((void *)baseAddress,
                     ROUND_UP(size),
                     PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE,
                     -1, 0);
    if(mem == (void *)-1) throw "Out of memory?";
    if(mem != (void *)baseAddress) throw "Overlapping with other regions?";
#ifdef ARCH_X86_64
    auto tp = (char *)mem;
#elif defined(ARCH_AARCH64)
    auto tp = (char *)mem + sizeof(struct my_pthread);
#endif
    auto addr = reinterpret_cast<address_t>(tp);
    if(tlsList) {
        for(auto tls : *tlsList) {
            tls->loadTo(addr);
            addr += tls->getSize();
        }
    }

    return tp;
}

void *DataLoader::loadLibraryTLSData(Module *module, address_t baseAddress) {
    auto tlsList = module->getTLSList();
    if(!tlsList) return nullptr;
    size_t size = 0;
    for(auto tls : *tlsList) {
        size += tls->getSize();
    }

    if(size) {
        LOG(1, "mapping TLS region into memory at 0x" << std::hex << baseAddress);
        void *mem = mmap((void *)baseAddress,
                         ROUND_UP(size),
                         PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE,
                         -1, 0);
        if(mem == (void *)-1) throw "Out of memory?";
        if(mem != (void *)baseAddress) throw "Overlapping with other regions?";
        auto addr = reinterpret_cast<address_t>(mem);
        for(auto tls : *tlsList) {
            tls->loadTo(addr);
            addr += tls->getSize();
        }
        tlsList->resolveRelocs(module->getElfSpace()->getElfMap());

        return mem;
    }

    return nullptr;
}
#endif

void *DataLoader::mapTLS(DataRegion *tls, address_t baseAddress) {
    if(!tls) return nullptr;

    LOG(1, "mapping TLS region into memory at 0x" << std::hex << baseAddress);
    void *mem = mmap((void *)baseAddress,
                     ROUND_UP(tls->getSize()),
                     PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE,
                     -1, 0);
    if(mem == (void *)-1) throw "Out of memory?";
    if(mem != (void *)baseAddress) throw "Overlapping with other regions?";
    auto addr = reinterpret_cast<address_t>(mem);
    copyTLSData(tls, addr);
    return mem;
}

void DataLoader::copyTLSData(DataRegion *tls, address_t loadAddress) {
    auto phdr = tls->getPhdr();
    address_t sourceAddr = elfMap->getBaseAddress() + phdr->p_vaddr;
    char *source = reinterpret_cast<char *>(sourceAddr);
    char *output = reinterpret_cast<char *>(loadAddress);

    std::memcpy(output, source, phdr->p_filesz);
    std::memset(output + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);

    tls->updateAddressFor(loadAddress);
}
