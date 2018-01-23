#include <cstdio>
#include <cstring>
#include "reloc.h"
#include "symbol.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dreloc
#include "log/log.h"

#define RELA_PREFIX ".rela"

std::string Reloc::getSymbolName() const {
    return symbol ? symbol->getName() : "???";
}

void RelocSection::add(Reloc *reloc) {
    relocList.push_back(reloc);
}

bool RelocList::add(Reloc *reloc) {
    relocList.push_back(reloc);
    address_t address = reloc->getAddress();

    // return true on success (no existing duplicate element)
    return relocMap.insert(std::make_pair(address, reloc)).second;
}

Reloc *RelocList::find(address_t address) {
    auto it = relocMap.find(address);
    return (it != relocMap.end() ? (*it).second : nullptr);
}

RelocSection *RelocList::getSection(const std::string &name) {
    auto it = sectionList.find(name);
    return (it != sectionList.end() ? (*it).second : nullptr);
}

RelocList *RelocList::buildRelocList(ElfMap *elf, SymbolList *symbolList,
    SymbolList *dynamicSymbolList) {

    RelocList *list = new RelocList();

    CLOG(0, "building relocation list");
    std::vector<void *> sectionList = elf->findSectionsByType(SHT_RELA);
    for(void *p : sectionList) {
        // Note: 64-bit x86 always uses RELA relocations (not REL),
        // according to readelf source: see the function guess_is_rela()
        ElfXX_Shdr *s = static_cast<ElfXX_Shdr *>(p);

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

        // We don't have the appropriate symbol section for these relocations.
        // This can happen when a shared object is statically linked.
        if(!currentSymbolList) continue;

        ElfXX_Rela *data = reinterpret_cast<ElfXX_Rela *>(
            elf->getCharmap() + s->sh_offset);

        size_t count = s->sh_size / sizeof(*data);
        for(size_t i = 0; i < count; i ++) {
            ElfXX_Rela *r = &data[i];
            auto symbolIndex = ELFXX_R_SYM(r->r_info);
            Symbol *sym = nullptr;
            if(symbolIndex > 0) {
                sym = currentSymbolList->get(symbolIndex);
            }

            address_t address = r->r_offset;
            auto type = ELFXX_R_TYPE(r->r_info);

            if(elf->isObjectFile()) {
                // If this relocation refers to a known section, add that
                // section's virtual address to the relocation address.
                // This is currently only applicable in object files.
                if(std::strncmp(RELA_PREFIX, name, std::strlen(RELA_PREFIX)) == 0) {
                    auto s = elf->findSection(name + std::strlen(RELA_PREFIX));
                    if(s) {
                        address += s->getVirtualAddress();
                    }
                }
            }

            Reloc *reloc = new Reloc(
                address,                                // address
                type,                                   // type
                ELFXX_R_SYM(r->r_info),                 // symbol index
                sym,
                r->r_addend                             // addend
            );

            CLOG0(2, "    reloc at address 0x%08lx, type %d, target [%s]\n",
                reloc->getAddress(), reloc->getType(),
                reloc->getSymbolName().c_str());

            if(!list->add(reloc)) {
                CLOG0(1, "ignoring duplicate relocation for %lx\n",
                      reloc->getAddress());
            }
            else {
                list->makeOrGetSection(name, s)->add(reloc);
            }
        }
    }

    return list;
}

RelocSection *RelocList::makeOrGetSection(const std::string &name,
    ElfXX_Shdr *s) {

    auto section = getSection(name);
    if(section) return section;

    if(s->sh_flags & SHF_INFO_LINK) {
        section = new RelocSection(name, s->sh_info);
    }
    else {
        section = new RelocSection(name);
    }
    sectionList[name] = section;
    return section;
}
