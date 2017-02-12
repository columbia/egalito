#include <algorithm>  // for std::sort
#include <cstdio>
#include <sstream>
#include <string.h>
#include <elf.h>
#include "symbol.h"
#include "elfmap.h"
#include "sharedlib.h"
#include "log/log.h"

bool SymbolList::add(Symbol *symbol, size_t index) {
    // Can't check just by name since it may not be unique
    //auto it = symbolMap.find(symbol->getName());
    //if(it != symbolMap.end()) return false;

    symbolList.push_back(symbol);
    if(indexMap.size() <= index) indexMap.resize(index + 1);
    indexMap[index] = symbol;
    symbolMap[symbol->getName()] = symbol;
    spaceMap[symbol->getAddress()] = symbol;
    return true;
}

void SymbolList::addAlias(Symbol *symbol, size_t otherIndex) {
    if(indexMap.size() <= otherIndex) indexMap.resize(otherIndex + 1);
    indexMap[otherIndex] = symbol;
}

Symbol *SymbolList::get(size_t index) {
    if(index >= indexMap.size()) return nullptr;
    return indexMap[index];
}

Symbol *SymbolList::find(const char *name) {
    auto it = symbolMap.find(name);
    if(it != symbolMap.end()) {
        return (*it).second;
    }
    else {
        return nullptr;
    }
}

Symbol *SymbolList::find(address_t address) {
    auto it = spaceMap.find(address);
    if(it != spaceMap.end()) {
        return (*it).second;
    }
    else {
        return nullptr;
    }
}

SymbolList *SymbolList::buildSymbolList(SharedLib *library) {
    ElfMap *elfMap = library->getElfMap();
    Elf64_Shdr *s = (Elf64_Shdr *)elfMap->findSectionHeader(".symtab");
    if(s && s->sh_type == SHT_SYMTAB) {
        return buildSymbolList(elfMap);
    }
    else {
        auto altFile = library->getAlternativeSymbolFile();
        if(altFile.size() > 0) {
            try {
                // we intentionally do not free this symbolFile; it
                // needs to stay mapped into memory so strings remain valid
                ElfMap *symbolFile = new ElfMap(altFile.c_str());
                return buildSymbolList(symbolFile);
            }
            catch(const char *s) {
                // the debug symbol file does not exist
                return nullptr;
            }
        }
    }

    return nullptr;
}

SymbolList *SymbolList::buildSymbolList(ElfMap *elfmap) {
    SymbolList *list = new SymbolList();
    std::map<address_t, Symbol *> seen;

    Elf64_Shdr *s = (Elf64_Shdr *)elfmap->findSectionHeader(".symtab");
    if(!s || s->sh_type != SHT_SYMTAB) throw "No symtab in ELF\n";

    Elf64_Sym *sym = (Elf64_Sym *)elfmap->findSection(".symtab");

    // look through symbols for ones of type FUNC and GLOBAL
    int symcount = s->sh_size / s->sh_entsize;
    for(int j = 0; j < symcount; j ++, sym ++) {
        // sym->st_shndx will be 0 for load-time relocations
        if((ELF64_ST_TYPE(sym->st_info) == STT_FUNC
                || ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC)  // strcmp etc
            && (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL
                || ELF64_ST_BIND(sym->st_info) == STB_LOCAL
                || ELF64_ST_BIND(sym->st_info) == STB_WEAK)
            && sym->st_shndx > 0) {

            address_t address = sym->st_value;
            size_t size = sym->st_size;
            const char *name = elfmap->getStrtab() + sym->st_name;
#if 1 // Get entry point
            if(!strcmp(name, "_start") && !sym->st_size) {
#ifdef ARCH_X86_64
                size = 42; // no really! :)
#elif defined(ARCH_AARCH64)
                size = 44; // this does not include embedded following literals
#endif
            }

            if(!strcmp(name, "_init") && !sym->st_size) {
                Elf64_Shdr *s = (Elf64_Shdr *)elfmap->findSectionHeader(".init");
                if(s) size = s->sh_size;
            }
#endif
            //auto index = sym->st_shndx;
#if 0
            symbol.is_ifunc = (ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC);
            symbol.is_private = (ELF64_ST_BIND(sym->st_info) == STB_LOCAL);

            /* --- libgcc/auto-generated cases --- */

            if(!strcmp(symbol.name, "_start") && !symbol.size) {
                symbol.size = 42;  // no really! :)
            }
            if(!strcmp(symbol.name, "_init") && !symbol.size) {
                //symbol.size = 26;//14;
                symbol.size = get_elf_init_size(elf);
                printf("FIX symbol _init size to 0x%lx\n", symbol.size);
            }
            if(!strcmp(symbol.name, "__do_global_dtors_aux") && !symbol.size) {
                symbol.size = 50;  // size from bzip2
                VERIFY_BYTES(0, 2, 0xc3f3ul);
            }
            if(!strcmp(symbol.name, "deregister_tm_clones") && !symbol.size) {
                symbol.size = 54;  // size from libpthread on Linux 4.3
                VERIFY_BYTES(-9, 2, 0xe0fful);
            }
            if(!strcmp(symbol.name, "register_tm_clones") && !symbol.size) {
                symbol.size = 70;  // size from libpthread on Linux 4.3
                VERIFY_BYTES(-9, 2, 0xe2fful);
            }
            if(!strcmp(symbol.name, "frame_dummy") && !symbol.size) {
                symbol.size = 53;  // size from bzip2
                VERIFY_BYTES(0, 8, 0xe900000000801f0ful);
            }

            /* --- ld.so cases --- */

            // uses direct reference to GOT (upper 32 bits)
            if(!strcmp(symbol.name, "__tls_get_addr")) continue;

            /* --- libc cases --- */

            if(!strcmp(symbol.name, "__strcasecmp_ssse3")) {
                symbol.size += 8502;  // size of __strcasecmp_l_ssse3
            }
            if(!strcmp(symbol.name, "__strncasecmp_ssse3")) {
                symbol.size += 9542;  // size of __strncasecmp_l_ssse3
            }

            /* --- libm cases --- */

            // can't parse FMA4 instructions
            size_t len = strlen(symbol.name);
            if(len > 5 && !strcmp(symbol.name + len - 5, "_fma4")) continue;
            //if(len > 4 && !strcmp(symbol.name + len - 4, "_avx")) continue;
            if((symbol.address & 0x55000) == 0x55000
                && (!strcmp(symbol.name, "bsloww")
                || !strcmp(symbol.name, "csloww")
                || !strcmp(symbol.name, "bsloww1")
                || !strcmp(symbol.name, "bsloww2")
                || !strcmp(symbol.name, "csloww1"))) {

                continue;
            }
#endif
            // don't try to figure out the size when it is zero
            if(size == 0) continue;


            auto prev = seen.find(address);
            if(prev != seen.end()) {
                if((*prev).second->getSize() == size) {
                    (*prev).second->addAlias(name);
                    list->addAlias((*prev).second, j);  // not required?
                }
                else {
                    CLOG0(0, "OVERLAPPING symbol, address 0x%lx [%s], not adding\n",
                        address, name);
                }
            }
            else {
                Symbol *symbol = new Symbol{address, size, name};
                CLOG0(1, "symbol #%d, address 0x%08lx, size %-8ld [%s]\n",
                    (int)j, address, size, name);
                list->add(symbol, (size_t)j);
            }
        }

#if 0
        if((ELF64_ST_TYPE(sym->st_info) == STT_OBJECT
            && (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL
                || ELF64_ST_BIND(sym->st_info) == STB_LOCAL
                || ELF64_ST_BIND(sym->st_info) == STB_WEAK))) {

            symbol_t object;
            object.address = sym->st_value;
            object.size = sym->st_size;
            object.name = elf->strtab + sym->st_name;
            object.index = sym->st_shndx;
            object.is_ifunc = 0;
            object.is_private = (ELF64_ST_BIND(sym->st_info) == STB_LOCAL);
            object.chunk = NULL;

            VECTOR_PUSH(symbol_t, object_list, object);
        }
#endif
    }

    list->sortSymbols();

    return list;
}

SymbolList *SymbolList::buildDynamicSymbolList(ElfMap *elfmap) {
    SymbolList *list = new SymbolList();
    std::map<address_t, Symbol *> seen;

    Elf64_Shdr *s = (Elf64_Shdr *)elfmap->findSectionHeader(".dynsym");
    if(!s || s->sh_type != SHT_DYNSYM) throw "No dynamic symtab in ELF\n";

    Elf64_Sym *sym = (Elf64_Sym *)elfmap->findSection(".dynsym");

    // look through symbols for ones of type FUNC and GLOBAL
    int symcount = s->sh_size / s->sh_entsize;
    for(int j = 0; j < symcount; j ++, sym ++) {
        // sym->st_shndx will be 0 for load-time relocations
        if((ELF64_ST_TYPE(sym->st_info) == STT_FUNC
                || ELF64_ST_TYPE(sym->st_info) == STT_GNU_IFUNC)  // strcmp etc
            && (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL
                || ELF64_ST_BIND(sym->st_info) == STB_LOCAL
                || ELF64_ST_BIND(sym->st_info) == STB_WEAK)
            /*&& sym->st_shndx > 0*/) {

            address_t address = sym->st_value;
            size_t size = sym->st_size;
            const char *name = elfmap->getDynstrtab() + sym->st_name;
            //auto index = sym->st_shndx;

            Symbol *symbol = new Symbol{address, size, name};
            CLOG0(1, "dynamic symbol #%d, index %d, [%s]\n",
                (int)list->symbolList.size(), j, name);
            list->add(symbol, (size_t)j);
        }
    }

    list->sortSymbols();

    return list;
}

void SymbolList::sortSymbols() {
    sortedSymbolList = symbolList;
    std::sort(sortedSymbolList.begin(), sortedSymbolList.end(),
        [](Symbol *a, Symbol *b) {
            return a->getAddress() < b->getAddress();
        });
}
