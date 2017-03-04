#include <algorithm>  // for std::sort
#include <cstdio>
#include <sstream>
#include <string.h>
#include <elf.h>
#include "symbol.h"
#include "elfmap.h"
#include "sharedlib.h"
#include "log/log.h"

bool Symbol::isFunction() const {
    return (symbolType == TYPE_FUNC || symbolType == TYPE_IFUNC)
        && size > 0 && index > 0 && !aliasFor;
}

bool SymbolList::add(Symbol *symbol, size_t index) {
    // Can't check just by name since it may not be unique
    //auto it = symbolMap.find(symbol->getName());
    //if(it != symbolMap.end()) return false;

    symbolList.push_back(symbol);
    if(indexMap.size() <= index) indexMap.resize(index + 1);
    indexMap[index] = symbol;
    if(symbolMap.find(symbol->getName()) == symbolMap.end()) {
        symbolMap[symbol->getName()] = symbol;
    }
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

Symbol *SymbolList::findSizeZero(SymbolList *list, const char *sym) {
    auto s = list->find(sym);
    return (s && s->getSize() == 0 ? s : nullptr);
}

SymbolList *SymbolList::buildSymbolList(ElfMap *elfmap) {
    auto list = buildAnySymbolList(elfmap, ".symtab", SHT_SYMTAB);

    if(auto s = findSizeZero(list, "_start")) {
#ifdef ARCH_X86_64
        s->setSize(42);  // no really! :)
#elif defined(ARCH_AARCH64)
        s->setSize(56);  // this does not include embedded following literals
#endif
        s->setType(Symbol::TYPE_FUNC);  // sometimes UNKNOWN
    }

    if(auto s = findSizeZero(list, "_init")) {
        auto init = static_cast<Elf64_Shdr *>(elfmap->findSectionHeader(".init"));
        if(init) s->setSize(init->sh_size);
    }

    std::map<address_t, Symbol *> seen;
    for(auto sym : *list) {
        auto prev = seen.find(sym->getAddress());
        if(prev != seen.end()) {
            auto prevSym = (*prev).second;
            if(prevSym->getSize() == sym->getSize()) {
                sym->setAliasFor(prevSym);
                prevSym->addAlias(sym);
            }
            else {
                CLOG0(0, "OVERLAPPING symbol, address 0x%lx [%s], not adding\n",
                    sym->getAddress(), sym->getName());
            }
        }
        else {
            seen[sym->getAddress()] = sym;
        }
    }

    return list;
}

SymbolList *SymbolList::buildDynamicSymbolList(ElfMap *elfmap) {
    return buildAnySymbolList(elfmap, ".dynsym", SHT_DYNSYM);
}

SymbolList *SymbolList::buildAnySymbolList(ElfMap *elfmap,
    const char *sectionName, unsigned sectionType) {

    SymbolList *list = new SymbolList();

    auto s = static_cast<Elf64_Shdr *>(elfmap->findSectionHeader(sectionName));
    if(!s || s->sh_type != sectionType) {
        LOG(1, "Warning: no symbol table " << sectionName << " in ELF file");
        return list;
    }

    const char *strtab = (sectionType == SHT_DYNSYM
        ? elfmap->getDynstrtab() : elfmap->getStrtab());

    auto sym = static_cast<Elf64_Sym *>(elfmap->findSection(sectionName));

    int symcount = s->sh_size / s->sh_entsize;
    for(int j = 0; j < symcount; j ++, sym ++) {
        Symbol::SymbolType type;
        switch(ELF64_ST_TYPE(sym->st_info)) {
        case STT_FUNC:      type = Symbol::TYPE_FUNC; break;
        case STT_GNU_IFUNC: type = Symbol::TYPE_IFUNC; break;
        case STT_OBJECT:    type = Symbol::TYPE_OBJECT; break;
        case STT_NOTYPE:    type = Symbol::TYPE_UNKNOWN; break;
        default: continue;
        }

        Symbol::BindingType bind;
        switch(ELF64_ST_BIND(sym->st_info)) {
        case STB_LOCAL:     bind = Symbol::BIND_LOCAL; break;
        case STB_GLOBAL:    bind = Symbol::BIND_GLOBAL; break;
        case STB_WEAK:      bind = Symbol::BIND_WEAK; break;
        default: continue;
        }

        address_t address = sym->st_value;
        size_t size = sym->st_size;
        const char *name = strtab + sym->st_name;

        // sym->st_shndx will be 0 for load-time relocations in dynsym
        auto index = sym->st_shndx;

        Symbol *symbol = new Symbol(address, size, name, type, bind, index);
        CLOG0(1, "%s symbol #%d, index %d, [%s]\n", sectionName,
            (int)list->symbolList.size(), j, name);
        list->add(symbol, (size_t)j);
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
