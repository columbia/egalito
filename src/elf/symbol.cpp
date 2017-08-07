#include <algorithm>  // for std::sort
#include <cstdio>
#include <sstream>
#include <string.h>
#include <elf.h>
#include "symbol.h"
#include "elfmap.h"
#include "sharedlib.h"
#include "elfxx.h"
#include "unionfind.h"

#undef DEBUG_GROUP
#define DEBUG_GROUP dsymbol
#include "log/log.h"

class SymbolAliasFinder : private UnionFind {
private:
    std::vector<Symbol *> sortedList;

public:
    SymbolAliasFinder(SymbolList *list);

    void constructByAddress();
    Symbol *getSymbol(size_t i) const { return sortedList[i]; }
    size_t getRepresentativeIndex(size_t i) { return find(i); }

private:
    virtual void setEdge(size_t x1, size_t x2);
};

bool Symbol::isFunction() const {
#if 0
    LOG(1, "function check for [" << name << "]: type="
        << symbolType
        << ", size=" << size
        << ", index=" << index
        << ", aliasFor=" << (aliasFor ? aliasFor->getName() : "n/a"));
#endif
    return (symbolType == TYPE_FUNC || symbolType == TYPE_IFUNC)
        && size > 0 && shndx > 0 && !aliasFor;
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
    if(symbol->getType() != Symbol::TYPE_SECTION
        && symbol->getName()[0] != '$') {

        spaceMap[symbol->getAddress()] = symbol;
    }
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
        auto sym = (*it).second;
        if(sym->getAliasFor()) {
            sym = sym->getAliasFor();
        }
        return sym;
    }
    else {
        return nullptr;
    }
}

Symbol *SymbolList::find(address_t address) {
    auto it = spaceMap.find(address);
    if(it != spaceMap.end()) {
        auto sym = (*it).second;
        if(sym->getAliasFor()) {
            sym = sym->getAliasFor();
        }
        return sym;
    }
    else {
        return nullptr;
    }
}

SymbolList *SymbolList::buildSymbolList(SharedLib *library) {
    ElfMap *elfMap = library->getElfMap();
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
        }
    }

    auto section = elfMap->findSection(".symtab");
    if(section && section->getHeader()->sh_type == SHT_SYMTAB) {
        return buildSymbolList(elfMap);
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
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        // this is harmful since there are two _start()
        //s->setSize(56);  // this does not include embedded following literals
#endif
        s->setType(Symbol::TYPE_FUNC);  // sometimes UNKNOWN
    }

    if(auto s = findSizeZero(list, "_init")) {
        auto init = elfmap->findSection(".init");
        if(init) s->setSize(init->getHeader()->sh_size);
    }
    if(auto s = findSizeZero(list, "_fini")) {
        auto fini = elfmap->findSection(".fini");
        if(fini) s->setSize(fini->getHeader()->sh_size);
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

    SymbolAliasFinder aliasFinder(list);
    aliasFinder.constructByAddress();

    for(size_t i = 0; i < list->getCount(); i++) {
        auto rep = aliasFinder.getRepresentativeIndex(i);
        if(rep != i) {
            auto sym = aliasFinder.getSymbol(i);
            auto repSym = aliasFinder.getSymbol(rep);
            sym->setAliasFor(repSym);
            repSym->addAlias(sym);
            LOG(1, "ALIAS: " << repSym->getName() << " : " << sym->getName());
        }
    }

    std::map<std::string, Symbol *> seenNamed;
    for(auto sym : *list) {
        if(!*sym->getName()) continue;  // empty names are fine

        // duplicate names for LOCAL functions (e.g. libm) are fine
        if(sym->getBind() == Symbol::BIND_LOCAL) continue;

        // don't alias SECTIONs with other types (e.g. first FUNC in .text) or FILEs with other types
        if(sym->getType() == Symbol::TYPE_SECTION || sym->getType() == Symbol::TYPE_FILE) continue;

        auto prev = seenNamed.find(sym->getName());
        if(prev != seenNamed.end()) {
            auto prevSym = (*prev).second;

            CLOG(0, "SAME NAME symbol [%s] at addresses 0x%lx and 0x%lx",
                sym->getName(), prevSym->getAddress(), sym->getAddress());


            if(!sym->getAliasFor()) sym->setAliasFor(prevSym);
            prevSym->addAlias(sym);
        }
        else {
            seenNamed[sym->getName()] = sym;
        }
    }

    return list;
}

SymbolList *SymbolList::buildDynamicSymbolList(ElfMap *elfmap) {
    auto list = buildAnySymbolList(elfmap, ".dynsym", SHT_DYNSYM);

    SymbolVersionList versionList(elfmap);
    for(auto sym : *list) {
        auto index = sym->getIndex();
        auto verName = versionList.getVersionName(index);
        bool verHidden = versionList.isHidden(index);

        LOG(10, "symbol " << sym->getName() << " has version " << verName);
        sym->setVersion(new SymbolVersion(verName, verHidden));
    }

    return list;
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

    auto sym = elfmap->getSectionReadPtr<ElfXX_Sym *>(section);
    auto s = section->getHeader();
    int symcount = s->sh_size / s->sh_entsize;
    for(int j = 0; j < symcount; j ++, sym ++) {
        auto type = Symbol::typeFromElfToInternal(sym->st_info);
        auto bind = Symbol::bindFromElfToInternal(sym->st_info);

        address_t address = sym->st_value;
        size_t size = sym->st_size;
        const char *name = strtab + sym->st_name;

#if 0
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
#endif

        // sym->st_shndx will be 0 for load-time relocations in dynsym
        auto shndx = sym->st_shndx;

        if(elfmap->isObjectFile()) {
            LOG0(1, "symbol name: " << sym->st_name << " shndx " << shndx);
            auto symSection = elfmap->findSection(shndx);
            // will be null if COM section...
            if(symSection) {
                // Convert Offset to Virtual address.
                address += symSection->getVirtualAddress();
            }
        }

        Symbol *symbol = new Symbol(address, size, name, type, bind, j, shndx);
        CLOG0(1, "%s symbol #%d, index %d, [%s] %lx\n", sectionName,
            (int)list->symbolList.size(), j, name, address);
        list->add(symbol, (size_t)j);
    }

    return list;
}

size_t SymbolList::estimateSizeOf(Symbol *symbol) {
    auto it = spaceMap.upper_bound(symbol->getAddress());
    while(it != spaceMap.end()) {
        Symbol *other = (*it).second;
        // for AARCH64, if the next symbol is mapping symbol, then it is
        // still part of the same function
        if(!strcmp(other->getName(), "$d")) {
            ++it;
            continue;
        }
        return other->getAddress() - symbol->getAddress();
    }

    return 0;
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
    switch(ELFXX_ST_TYPE(type)) {
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
    switch(ELFXX_ST_BIND(type)) {
    case STB_LOCAL:     return Symbol::BIND_LOCAL;
    case STB_GLOBAL:    return Symbol::BIND_GLOBAL;
    default:            return Symbol::BIND_WEAK;
    }
}

bool SymbolVersionList::isHidden(size_t symbolIndex) const {
    if(hasVersionInfo()) {
        return verList[symbolIndex] & 0x8000;
    }
    return false;
}

const char *SymbolVersionList::getVersionName(size_t symbolIndex) const {
    if(hasVersionInfo()) {
        auto it = nameList.find(getVersionIndex(symbolIndex));
        if(it != nameList.end()) {
            return it->second;
        }
    }
    return "";
}

void SymbolVersionList::dump() const {
    LOG(1, "Number of version symbols: " << std::dec << verList.size());
    LOG(1, "Number of versions: " << nameList.size());
    for(auto n : nameList) {
        LOG(1, "name[" << n.first << "] " << n.second);
    }
}

SymbolVersionList::SymbolVersionList(ElfMap *elfmap) {
    auto ver_section = elfmap->findSection(".gnu.version");
    if(!ver_section) {
        return;
    }

    const char *strtab = elfmap->getDynstrtab();

    auto versym = elfmap->getSectionReadPtr<ElfXX_Versym *>(ver_section);
    auto s = ver_section->getHeader();
    int count = s->sh_size / s->sh_entsize;
    LOG(10, "Section .gnu.version has " << count << " entries");

    for(int i = 0; i < count; i++, versym++) {
        addVersion(*versym);
    }
    addName(0, "");
    addName(1, "");

    auto d_section = elfmap->findSection(".gnu.version_d");
    if(d_section) {
        auto verdef = elfmap->getSectionReadPtr<ElfXX_Verdef *>(d_section);
        auto s = d_section->getHeader();
        size_t size = s->sh_size;
        LOG(10, "Section .gnu.version_d has " << size << " bytes");
        size_t offset = 0;
        do {
            CLOG(10, "flags: %04x, ndx: %04x, cnt: %04x, hash: %08x, aux: %08x, next: %08x",
                 verdef->vd_flags, verdef->vd_ndx, verdef->vd_cnt,
                 verdef->vd_hash, verdef->vd_aux, verdef->vd_next);
            auto aux = reinterpret_cast<ElfXX_Verdaux *>(
                (char *)verdef + verdef->vd_aux);
            addName(verdef->vd_ndx, strtab + aux->vda_name);

            size_t aoffset = 0;
            // the first one (j = 0) is the name of this version and the second
            // one (j = 1) is the name of the parent
            for(size_t j = 0; j < verdef->vd_cnt; j++) {
                CLOG(10, "name: %08x, next: %08x", aux->vda_name, aux->vda_next);
                CLOG(10, "name in strtab: %s", strtab + aux->vda_name);
                aoffset = aux->vda_next;
                aux = reinterpret_cast<ElfXX_Verdaux *>((char *)aux + aoffset);
            }


            offset = verdef->vd_next;
            verdef = reinterpret_cast<ElfXX_Verdef *>((char *)verdef + offset);
        } while (offset > 0);
    }

    auto r_section = elfmap->findSection(".gnu.version_r");
    if(r_section) {
        auto verneed = elfmap->getSectionReadPtr<ElfXX_Verneed *>(r_section);
        auto s = r_section->getHeader();
        size_t size = s->sh_size;
        LOG(10, "Section .gnu.version_r has " << size << " bytes");
        size_t offset = 0;
        do {
            CLOG(10, "version: %04x, cnt: %04x, file: %08x, aux: %08x, next: %08x",
                 verneed->vn_version, verneed->vn_cnt, verneed->vn_file,
                 verneed->vn_aux, verneed->vn_next);
            auto aux = reinterpret_cast<ElfXX_Vernaux *>(
                (char *)verneed + verneed->vn_aux);
            size_t aoffset = 0;
            for(size_t j = 0; j < verneed->vn_cnt; j++) {
                addName(aux->vna_other, strtab + aux->vna_name);

                // 'other' seemed to be decoded as Version
                CLOG(10, "hash: %08x, flags: %04x, other(unused): %04x, name: %08x, next: %08x",
                     aux->vna_hash, aux->vna_flags, aux->vna_other,
                     aux->vna_name, aux->vna_next);
                CLOG(10, "name in strtab: %s", strtab + aux->vna_name);
                aoffset = aux->vna_next;
                aux = reinterpret_cast<ElfXX_Vernaux *>((char *)aux + aoffset);
            }

            offset = verneed->vn_next;
            verneed = reinterpret_cast<ElfXX_Verneed *>((char *)verneed + offset);
        } while (offset > 0);
    }

    dump();
}

SymbolAliasFinder::SymbolAliasFinder(SymbolList *list)
    : UnionFind(list->getCount()), sortedList(list->begin(), list->end()) {
    std::sort(sortedList.begin(), sortedList.end(),
        [](Symbol *a, Symbol *b) {
            return a->getAddress() < b->getAddress();
        });
}

void SymbolAliasFinder::setEdge(size_t x1, size_t x2) {
    auto s1 = sortedList[x1];
    auto s2 = sortedList[x2];

    bool done = false;

    // section vs others
    if(s1->getType() != s2->getType()) {
        if(s1->getType() == Symbol::TYPE_SECTION) {
            parent[x1] = x2;
            done = true;
        }
        else if(s2->getType() == Symbol::TYPE_SECTION) {
            parent[x2] = x1;
            done = true;
        }
        else if(s1->getType() == Symbol::TYPE_FILE) {
            parent[x1] = x2;
            done = true;
        }
        else if(s2->getType() == Symbol::TYPE_FILE) {
            parent[x2] = x1;
            done = true;
        }
    }

    // normal symbol > mapping symbol
    if(!done) {
        if(s1->getBind() == Symbol::BIND_LOCAL && s1->getName()[0] == '$') {
            parent[x1] = x2;
            done = true;
        }
        else if(s2->getBind() == Symbol::BIND_LOCAL
            && s2->getName()[0] == '$') {

            parent[x2] = x1;
            done = true;
        }
    }

    // this seems to be a good heuristic
    if(!done) {
        if(strstr(s1->getName(), s2->getName())) {
            parent[x1] = x2;
            done = true;
        }
        else if(strstr(s2->getName(), s1->getName())) {
            parent[x2] = x1;
            done = true;
        }
    }

    if(!done) {
        if(strstr(s1->getName(), "@@")) {
            parent[x2] = x1;
            done = true;
        }
        else if(strstr(s2->getName(), "@@")) {
            parent[x1] = x2;
            done = true;
        }
        else if(strstr(s1->getName(), "@")) {
            parent[x1] = x2;
            done = true;
        }
        else if(strstr(s2->getName(), "@")) {
            parent[x2] = x1;
            done = true;
        }
    }

    if(!done) {
        if(s1->getBind() != s2->getBind()) {
            // weak symbols are the symbols that are usually used
            if(s1->getBind() == Symbol::BIND_LOCAL) {
                parent[x1] = x2;
                done = true;
            }
            else if(s2->getBind() == Symbol::BIND_LOCAL) {
                parent[x2] = x1;
                done = true;
            }
            else if(s1->getBind() == Symbol::BIND_GLOBAL) {
                parent[x2] = x1;
                done = true;
            }
            else if(s2->getBind() == Symbol::BIND_GLOBAL) {
                parent[x1] = x2;
                done = true;
            }
            else if(s1->getBind() == Symbol::BIND_WEAK) {
                parent[x2] = x1;
                done = true;
            }
            else if(s2->getBind() == Symbol::BIND_WEAK) {
                parent[x1] = x2;
                done = true;
            }
        }
    }

#if 1
    // we might need a DB of standard API names
    if(!done) {
        LOG(1, "setting an alias ARBITRARILY ("
            << s2->getName() << "->" << s1->getName() << ")");
        parent[x1] = x2;
    }
#endif
}

void SymbolAliasFinder::constructByAddress() {
    for(size_t i = 0; i < sortedList.size(); i++) {
        auto sym = sortedList[i];
        if(sym->getSectionIndex() == SHN_UNDEF) continue;
        //if(sym->getType() == Symbol::TYPE_SECTION) continue;
        if(sym->getType() == Symbol::TYPE_FILE) continue;

        for(size_t j = i + 1; j < sortedList.size(); j++) {
            auto sym2 = sortedList[j];
            if(sym->getAddress() != sym2->getAddress()) {
                break;
            }
            /* if(sym2->getSectionIndex() == SHN_UNDEF) continue; */
            if(sym2->getType() == Symbol::TYPE_SECTION) continue;
            if(sym2->getType() == Symbol::TYPE_FILE) continue;

            if(sym->getSectionIndex() == sym2->getSectionIndex()) {
                // we have to make an alias for this case too; otherwise
                // there is no way of getting to this symbol by address.
                // This is needed to get an object symbol from section
                // symbol obtained from a relocation
                //if(sym->getSize() == sym2->getSize())
                join(i, j);
            }
        }
    }
}

#if 0
bool MappingSymbol::isMappingSymbol(Symbol *symbol) {
    return symbol->getBind() == Symbol::BIND_LOCAL
        && symbol->getType() == Symbol::TYPE_UNKNOWN
        && symbol->getSectionIndex() != 0
        && symbol->getName()[0] == '$';
}

MappingSymbol::MappingType MappingSymbol::mappingFromElfToInternal(unsigned char type) {
  switch(type) {
  case 'a': return MappingSymbol::MAPPING_ARM;
  case 't': return MappingSymbol::MAPPING_THUMB;
  case 'x': return MappingSymbol::MAPPING_AARCH64;
  case 'd': return MappingSymbol::MAPPING_DATA;
  default:  return MappingSymbol::MAPPING_UNKNOWN;
  }
}

bool MappingSymbolList::add(MappingSymbol *symbol) {
  symbolList.push_back(symbol);
  symbolMap[symbol->getAddress()] = symbol;
  return true;
}

MappingSymbol *MappingSymbolList::find(address_t address) {
  MapType::iterator exact, range;

  exact = symbolMap.find(address);
  if (exact != symbolMap.end()) {
    return exact->second;
  }

  range=symbolMap.lower_bound(address);

  if (range != symbolMap.begin()) {
    return std::prev(range)->second;
  }

  return nullptr;
}

MappingSymbolList::ListType *MappingSymbolList::findSymbolsInRegion(address_t start, address_t end) {

  ListType *symbolsInRegion = new ListType();

  auto startSym = find(start);
  auto endSym = find(end);

  // If there is only 1 mapping symbol
  if (startSym == endSym) {
    symbolsInRegion->push_back(startSym);
    return symbolsInRegion;
  }

  MapType::iterator startIt, endIt;
  startIt = symbolMap.find(startSym->getAddress());
  endIt = symbolMap.find(endSym->getAddress());

  for(auto it = startIt; it != endIt; it++) {
    symbolsInRegion->push_back(it->second);
  }

  return symbolsInRegion;
}

MappingSymbolList *MappingSymbolList::buildMappingSymbolList(SymbolList *symbolList) {

    MappingSymbolList *list = new MappingSymbolList();

    MappingSymbol *prev = nullptr;

    for(auto sym : *symbolList) {
      if( MappingSymbol::isMappingSymbol(sym) ) {
        MappingSymbol *mappingSymbol = new MappingSymbol(sym);
        LOG(1, "Adding Mapping Symbol @ " << std::hex << mappingSymbol->getAddress() << " Type: " << mappingSymbol->getType());
        list->add(mappingSymbol);
        if(prev) {
          // Sec 4.5.5.1 - Each interval starts at the address defined by the
          // mapping symbol, and continues up to, but not including, the
          // address defined by the next (in address order) mapping symbol or
          // the end of the section.
          // See: http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044f/IHI0044F_aaelf.pdf
          size_t regionSize = mappingSymbol->getAddress() - prev->getAddress();
          // Size will be 0 for last mapping symbol. All subsequent addresses use the last mapping type.
          prev->setSize(regionSize);
        }

        prev = mappingSymbol;
      }
    }

    return list;
}
#endif
