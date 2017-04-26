#include <cstring>  // for memcpy, memset
#include <elf.h>
#include "tls.h"
#include "elf/elfmap.h"
#include "elf/reloc.h"
#include "log/log.h"

#if 0
void TLSList::buildTLSList(ElfMap *elf, RelocList *relocList, Module *module) {
    TLSList *list = nullptr;

    for(void *s : elf->getSegmentList()) {
        ElfXX_Phdr *phdr = static_cast<ElfXX_Phdr *>(s);
        if(phdr->p_type != PT_TLS) continue;
        if(!list) list = new TLSList();
        list->add(new TLSRegion(phdr, elf));
        LOG(1, "Found TLS region");
    }
    if(!list) return;

    if(list) {
        for(auto r : *relocList) {
#ifdef ARCH_X86_64
            if(r->getType() == R_X86_64_TPOFF64) {
                list->addReloc(r);
            }
#else
#ifdef R_AARCH64_TLS_TPREL64  // needed on older debian systems
            if(r->getType() == R_AARCH64_TLS_TPREL64) {
#else
            if(r->getType() == R_AARCH64_TLS_TPREL) {
#endif
                list->addReloc(r);
            }
#endif
        }
    }

    module->setTLSList(list);
}

void TLSList::TLSRegion::loadTo(address_t baseAddress) {
    char *output = reinterpret_cast<char *>(baseAddress);
    address_t sourceAddr = sourceElf->getBaseAddress() + phdr->p_vaddr;
    char *source = reinterpret_cast<char *>(sourceAddr);
    std::memcpy(output, source, phdr->p_filesz);
    std::memset(output + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);

    setAddress(baseAddress);
}

void TLSList::resolveRelocs(ElfMap *elf) {
    LOG(1, "TLSList::resolveRelocs has " << tlsList.size() << " tls regions");

    for(auto r : relocList) {
        auto location = elf->getBaseAddress() + r->getAddress();
        auto value = tlsList[0]->getAddress() + r->getAddend();
        LOG(1, "    resolve " << std::hex << location << " = " << value);
        *(unsigned long *)location = value;
    }
}
#endif
