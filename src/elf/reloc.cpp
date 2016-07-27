#include <cstdio>
#include <cstring>
#include "reloc.h"

bool RelocList::add(Reloc *reloc) {
    relocList.push_back(reloc);
    address_t address = reloc->getAddress();
    auto it = relocMap.find(address);
    if(it == relocMap.end()) {
        relocMap[address] = reloc;
        return true;
    }
    else {
        return false;
    }
}

RelocList RelocList::buildRelocList(ElfMap *elf) {
    RelocList list;

    std::vector<void *> sectionList
        = elf->findSectionsByType(SHT_RELA);
    for(void *p : sectionList) {
        // Note: 64-bit x86 always uses RELA relocations (not REL),
        // according to readelf source: see the function guess_is_rela()
        Elf64_Shdr *s = static_cast<Elf64_Shdr *>(p);

        // We never use debug relocations, and they often contain relative
        // addresses which cannot be dereferenced directly (segfault).
        // So ignore all sections with debug relocations.
        const char *name = elf->getSHStrtab() + s->sh_name;
        if(std::strstr(name, "debug")) continue;

        Elf64_Rela *data = reinterpret_cast<Elf64_Rela *>
            (elf->getCharmap() + s->sh_offset);

        size_t count = s->sh_size / sizeof(*data);
        for(size_t i = 0; i < count; i ++) {
            Elf64_Rela *r = &data[i];
            Reloc *reloc = new Reloc(
                elf->getBaseAddress() + r->r_offset,    // address
                ELF64_R_TYPE(r->r_info),                // type
                ELF64_R_SYM(r->r_info),                 // symbol index
                r->r_addend                             // addend
            );

            std::printf("reloc at address 0x%08lx, type %d, target %lu\n",
                reloc->getAddress(), reloc->getType(),
                reloc->getSymbolIndex());

            /*if(reloc.type == R_X86_64_COPY) {
                Elf64_Sym *dynsym = (Elf64_Sym *)
                    (elfspace->elf->map + elfspace->elf->dynsym->sh_offset);
                const char *name = elfspace->elf->dynstr
                    + dynsym[reloc.symbol].st_name;
                reloc.copy_reloc_name = name;
                printf("Found a copy reloc at %lx for [%s]\n", reloc.address, name);
                list.add(reloc);
            }
            else*/ if(!list.add(reloc)) {
                std::printf("ignoring duplicate relocation for %lx\n", reloc->getAddress());
            }
        }
    }

    return std::move(list);
}
