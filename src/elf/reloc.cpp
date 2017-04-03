#include <cstdio>
#include <cstring>
#include "reloc.h"
#include "symbol.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP reloc
#include "log/log.h"

std::string Reloc::getSymbolName() const {
    return symbol ? symbol->getName() : "???";
}

Elf64_Rela Reloc::makeRela() const {
    Elf64_Rela rela;
    rela.r_offset   = address;
    rela.r_info     = ELF64_R_INFO(symbolIndex, type);
    rela.r_addend   = addend;
    return std::move(rela);
}

bool RelocList::add(Reloc *reloc) {
    relocList.push_back(reloc);
    address_t address = reloc->getAddress();
#if 0
    auto it = relocMap.find(address);
    if(it == relocMap.end()) {
        relocMap[address] = reloc;
        return true;
    }
    else {
        return false;
    }
#else
    return relocMap.insert(std::make_pair(address, reloc)).second;
#endif
}

Reloc *RelocList::find(address_t address) {
    auto it = relocMap.find(address);
    return (it != relocMap.end() ? (*it).second : nullptr);
}

RelocList *RelocList::buildRelocList(ElfMap *elf, SymbolList *symbolList,
    SymbolList *dynamicSymbolList) {

    RelocList *list = new RelocList();

    CLOG(0, "building relocation list");
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
        LOG(1, "reloc section [" << name << ']');

        SymbolList *currentSymbolList = symbolList;
        if(std::strcmp(name, ".rela.plt") == 0
            || std::strcmp(name, ".rela.dyn") == 0) {

            currentSymbolList = dynamicSymbolList;
        }

        Elf64_Rela *data = reinterpret_cast<Elf64_Rela *>
            (elf->getCharmap() + s->sh_offset);

        size_t count = s->sh_size / sizeof(*data);
        for(size_t i = 0; i < count; i ++) {
            Elf64_Rela *r = &data[i];
            Symbol *sym = currentSymbolList->get(ELF64_R_SYM(r->r_info));

            address_t address = r->r_offset;
            auto type = ELF64_R_TYPE(r->r_info);
            //address += elf->getBaseAddress();

            if(!sym && type == R_X86_64_IRELATIVE) {
                sym = currentSymbolList->find(r->r_addend);
                LOG(3, "        IRELATIVE reloc refers to 0x" << std::hex << r->r_addend
                    << " [" << (sym ? sym->getName() : "???") << "]");
            }

            Reloc *reloc = new Reloc(
                address,                                // address
                type,                                   // type
                ELF64_R_SYM(r->r_info),                 // symbol index
                sym,
                r->r_addend                             // addend
            );


            CLOG0(2, "    reloc at address 0x%08lx, type %d, target [%s]\n",
                reloc->getAddress(), reloc->getType(),
                reloc->getSymbolName().c_str());

            /*if(reloc.type == R_X86_64_COPY) {
                Elf64_Sym *dynsym = (Elf64_Sym *)
                    (elfspace->elf->map + elfspace->elf->dynsym->sh_offset);
                const char *name = elfspace->elf->dynstr
                    + dynsym[reloc.symbol].st_name;
                reloc.copy_reloc_name = name;
                printf("Found a copy reloc at %lx for [%s]\n", reloc.address, name);
                list.add(reloc);
            }
            else*/ if(!list->add(reloc)) {
                CLOG0(1, "ignoring duplicate relocation for %lx\n", reloc->getAddress());
            }
        }
    }

    return list;
}
