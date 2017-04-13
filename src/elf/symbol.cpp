#include <algorithm>  // for std::sort
#include <cstdio>
#include <sstream>
#include <string.h>
#include <elf.h>
#include "symbol.h"
#include "elfmap.h"
#include "sharedlib.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dsymbol
#include "log/log.h"

bool Symbol::isFunction() const {
#if 0
    LOG(1, "function check for [" << name << "]: type="
        << symbolType
        << ", size=" << size
        << ", index=" << index
        << ", aliasFor=" << (aliasFor ? aliasFor->getName() : "n/a"));
#endif
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
    auto section = elfMap->findSection(".symtab");
    if(section && section->getHeader()->sh_type == SHT_SYMTAB) {
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
        auto init = elfmap->findSection(".init");
        if(init) s->setSize(init->getHeader()->sh_size);
    }

    // for musl only
    if(auto s = list->find("__memcpy_fwd")) {
        s->setType(Symbol::TYPE_FUNC);
    }
    /*if(auto s = list->find("__cp_begin")) {
        s->setType(Symbol::TYPE_FUNC);
    }*/

    for(auto sym : *list) {
        if(sym->getSize() == 0 && sym->getAddress() > 0) {
            size_t estimate = list->estimateSizeOf(sym);
            LOG(1, "estimate size of symbol ["
                << sym->getName() << "] to be " << std::dec << estimate);
            sym->setSize(estimate);
        }
    }

    std::map<address_t, Symbol *> seen;
    for(auto sym : *list) {
        // don't alias the null section index 0
        if (sym->getSectionIndex() == 0) continue;

        // don't alias SECTIONs with other types (e.g. first FUNC in .text) or FILEs with other types
        if(sym->getType() == Symbol::TYPE_SECTION || sym->getType() == Symbol::TYPE_FILE) continue;
#ifdef ARCH_AARCH64
        // skip mapping symbols in AARCH64 ELF
        if(sym->getName()[0] == '$') continue;
#endif

        auto prev = seen.find(sym->getAddress());
        if(prev != seen.end()) {
            auto prevSym = (*prev).second;

            if(prevSym->getSize() == sym->getSize()
                && prevSym->getBind() == sym->getBind()
                && prevSym->getSectionIndex() == sym->getSectionIndex()) {

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

    auto section = elfmap->findSection(sectionName);
    if(!section || section->getHeader()->sh_type != sectionType) {
        LOG(1, "Warning: no symbol table " << sectionName << " in ELF file");
        return list;
    }

    const char *strtab = (sectionType == SHT_DYNSYM
        ? elfmap->getDynstrtab() : elfmap->getStrtab());

    auto sym = elfmap->getSectionReadPtr<Elf64_Sym *>(section);
    auto s = section->getHeader();
    int symcount = s->sh_size / s->sh_entsize;
    for(int j = 0; j < symcount; j ++, sym ++) {
        auto type = Symbol::typeFromElfToInternal(sym->st_info);
        auto bind = Symbol::bindFromElfToInternal(sym->st_info);

        address_t address = sym->st_value;
        size_t size = sym->st_size;
        const char *name = strtab + sym->st_name;

        // Symbol versioning: some functions have @@GLIBC.* appended to the
        // name (exported functions?), others only have one '@'.
        auto specialVersion = strstr(name, "@@GLIBC");
        if(!specialVersion) specialVersion = strstr(name, "@GLIBC");
        if(specialVersion) {
            size_t len = specialVersion - name;
            char *newName = new char[len + 1];
            memcpy(newName, name, len);
            newName[len] = 0;
            name = newName;
        }


        // sym->st_shndx will be 0 for load-time relocations in dynsym
        auto shndx = sym->st_shndx;

        if (elfmap->isObjectFile()) {
            LOG0(1, "symbol name: " << sym->st_name << " shndx " << shndx);
            auto symSection = elfmap->findSection(shndx);
            // will be null if COM section...
            if (symSection) {
                // Convert Offset to Virtual address.
                address += symSection->getVirtualAddress();
            }
        }

        Symbol *symbol = new Symbol(address, size, name, type, bind, j, shndx);
        CLOG0(1, "%s symbol #%d, index %d, [%s]\n", sectionName,
            (int)list->symbolList.size(), j, name);
        list->add(symbol, (size_t)j);
    }

    list->sortSymbols();

    return list;
}

size_t SymbolList::estimateSizeOf(Symbol *symbol) {
    auto it = spaceMap.upper_bound(symbol->getAddress());
    if(it != spaceMap.end()) {
        Symbol *other = (*it).second;
        return other->getAddress() - symbol->getAddress();
    }

    return 0;
}

void SymbolList::sortSymbols() {
    sortedSymbolList = symbolList;
    std::sort(sortedSymbolList.begin(), sortedSymbolList.end(),
        [](Symbol *a, Symbol *b) {
            return a->getAddress() < b->getAddress();
        });
}

unsigned char Symbol::typeFromInternalToElf(SymbolType type) {
    switch(type) {
    case Symbol::TYPE_FUNC:     return STT_FUNC;
    case Symbol::TYPE_IFUNC:    return STT_GNU_IFUNC;
    case Symbol::TYPE_OBJECT:   return STT_OBJECT;
    case Symbol::TYPE_SECTION:  return STT_SECTION;
    case Symbol::TYPE_FILE:     return STT_FILE;
    default:                    return STT_NOTYPE;
    }
}

Symbol::SymbolType Symbol::typeFromElfToInternal(unsigned char type) {
    switch(ELF64_ST_TYPE(type)) {
    case STT_FUNC:     return Symbol::TYPE_FUNC;
    case STT_GNU_IFUNC:return Symbol::TYPE_IFUNC;
    case STT_OBJECT:   return Symbol::TYPE_OBJECT;
    case STT_SECTION:  return Symbol::TYPE_SECTION;
    case STT_FILE:     return Symbol::TYPE_FILE;
    default:           return Symbol::TYPE_UNKNOWN;
    }
}

unsigned char Symbol::bindFromInternalToElf(BindingType bind) {
    switch(bind) {
    case Symbol::BIND_LOCAL:  return STB_LOCAL;
    case Symbol::BIND_GLOBAL: return STB_GLOBAL;
    default:                  return STB_WEAK;
    }
}

Symbol::BindingType Symbol::bindFromElfToInternal(unsigned char type) {
    switch(ELF64_ST_BIND(type)) {
    case STB_LOCAL:     return Symbol::BIND_LOCAL;
    case STB_GLOBAL:    return Symbol::BIND_GLOBAL;
    default:            return Symbol::BIND_WEAK;
    }
}
