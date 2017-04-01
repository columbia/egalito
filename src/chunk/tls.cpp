#include <elf.h>
#include "tls.h"
#include "elf/elfmap.h"
#include "elf/reloc.h"
#include "log/log.h"

void TLSList::buildTLSList(ElfMap *elf, RelocList *relocList, Module *module) {

    TLSList *list = nullptr;

    for(void *s : elf->getSegmentList()) {
        Elf64_Phdr *phdr = static_cast<Elf64_Phdr *>(s);
        if(phdr->p_type != PT_TLS) continue;
        if(!list) list = new TLSList();
        list->add(new TLSRegion(phdr, elf));
    }

    for(auto r : *relocList) {
        if(r->getType() == R_AARCH64_TLS_TPREL) {
            list->addReloc(r);
        }
    }

    if(list) {
        module->setTLSList(list);
    }
}

void TLSList::TLSRegion::loadTo(address_t baseAddress) {
    char *output = reinterpret_cast<char *>(baseAddress);
    address_t sourceAddr = sourceElf->getBaseAddress() + phdr->p_vaddr;
    char *source = reinterpret_cast<char *>(sourceAddr);
    std::memcpy(output, source, phdr->p_filesz);
    std::memset(output + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);

    setAddress(baseAddress);
}


