#ifndef EGALITO_ELF_TLS_H
#define EGALITO_ELF_TLS_H

#include "chunk/chunk.h"
#include "chunk/concrete.h"
#include "types.h"

/*
 * How glibc handles TLS for AARCH64:
 *
 * For static binary,
 *  - struct pthread for main is in the heap (by __sbrk).
 *  - DTV is statically allocated in data section.
 *  - tpidr_el0 points to the end of the struct pthread
 *    where the pointer to DTV and private is allocated (i.e. TLS_DTV_AT_TP).
 *
 * When a pthread is created, similar structures are allocated on stack.
 *  - it has to copy original .tdata & .tbss (at load time or when
 *    referenced (i.e. __tls_get_addr() is called)).
 *  - it has to provide their address through __tls_get_addr().
 */

class ElfMap;
class RelocList;

class TLSList {
private:
    class TLSRegion : public DataRegion {
    private:
        ElfMap *sourceElf;
        Elf64_Phdr *phdr;
        address_t address;
    public:
        TLSRegion(Elf64_Phdr *phdr, ElfMap *elf) : sourceElf(elf), phdr(phdr) {}
        void setAddress(address_t address) { this->address = address; }
        address_t getAddress() const { return address; }
        void loadTo(address_t baseAddress);
        size_t getSize() const { return phdr->p_memsz; }
    };

    typedef std::vector<TLSRegion *> ListType;
    ListType tlsList;
    std::vector<Reloc *> relocList;

public:
    void add(TLSRegion *tls) { tlsList.push_back(tls); }

    ListType::iterator begin() { return tlsList.begin(); }
    ListType::iterator end() { return tlsList.end(); }

    void addReloc(Reloc *r) { relocList.push_back(r); }
    void resolveRelocs(ElfMap *elf);

    static void buildTLSList(ElfMap *elf, RelocList *relocList, Module *module);

};

#endif
