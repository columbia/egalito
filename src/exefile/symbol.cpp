#include <algorithm>  // for std::sort
#include <cstdio>
#include <sstream>
#include <string.h>
#include <elf.h>
#include "symbol.h"
#include "elf/elfmap.h"
#include "elf/sharedlib.h"
#include "elf/elfxx.h"

#ifdef USE_WIN64_PE
#include "pe/symbolparser.h"
#endif

#undef DEBUG_GROUP
#define DEBUG_GROUP dsymbol
#include "log/log.h"
#include "log/temp.h"

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

void SymbolListWithMapping::buildMappingList() {
    sortedMappingList.reserve(getCount());
    for(auto sym : *this) {
        if(sym->getName()[0] == '$') {
            sortedMappingList.push_back(sym);
        }
    }
    sortedMappingList.shrink_to_fit();
    std::sort(sortedMappingList.begin(), sortedMappingList.end(),
        [](Symbol *a, Symbol *b) {
            return a->getAddress() < b->getAddress(); });
}

Symbol *SymbolListWithMapping::findMappingBelowOrAt(Symbol *symbol) {
    auto it = std::lower_bound(
        sortedMappingList.begin(), sortedMappingList.end(), symbol,
        [](Symbol *a, Symbol *b) {  // b: symbol, continue if true
            return a->getAddress() < b->getAddress();
        });
    if(it != sortedMappingList.end()) {
        if((*it)->getAddress() == symbol->getAddress()) {
            if((*it)->getSectionIndex() == symbol->getSectionIndex()) {
                return *it;
            }
        }
    }
    if(it != sortedMappingList.begin()) {
        while(--it != sortedMappingList.begin()) {
            if((*it)->getSectionIndex() == symbol->getSectionIndex()) {
                return *(it);
            }
        }
    }
    return nullptr;
}

Symbol *SymbolListWithMapping::findMappingAbove(Symbol *symbol) {
    auto it = std::upper_bound(
        sortedMappingList.begin(), sortedMappingList.end(), symbol,
        [](Symbol *a, Symbol *b) {  // b: symbol, continue if false
            return a->getAddress() < b->getAddress();
        });
    while(it != sortedMappingList.end()) {
        if((*it)->getSectionIndex() == symbol->getSectionIndex()) {
            return *it;
        }
        ++it;
    }
    return nullptr;
}

size_t SymbolList::estimateSizeOf(Symbol *symbol) {
    auto it = spaceMap.upper_bound(symbol->getAddress());
    while(it != spaceMap.end()) {
        Symbol *other = (*it).second;
        // for AARCH64, if the next symbol is a mapping symbol, then it is
        // still part of the same function
        if(!strcmp(other->getName(), "$d")) {
            ++it;
            continue;
        }
        if(other->getSectionIndex() == symbol->getSectionIndex()) {
            return other->getAddress() - symbol->getAddress();
        }
        else {
            // maybe we can do better if we really need to
            return 0;
        }
    }

    return 0;
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
        LOG(9, "name[" << n.first << "] " << n.second);
    }
}

SymbolVersionList::SymbolVersionList(ElfMap *elfMap) {
    auto ver_section = elfMap->findSection(".gnu.version");
    if(!ver_section) {
        return;
    }

    const char *strtab = elfMap->getDynstrtab();

    auto versym = elfMap->getSectionReadPtr<ElfXX_Versym *>(ver_section);
    auto s = ver_section->getHeader();
    int count = s->sh_size / s->sh_entsize;
    LOG(10, "Section .gnu.version has " << count << " entries");

    for(int i = 0; i < count; i++, versym++) {
        addVersion(*versym);
    }
    addName(0, "");
    addName(1, "");

    auto d_section = elfMap->findSection(".gnu.version_d");
    if(d_section) {
        auto verdef = elfMap->getSectionReadPtr<ElfXX_Verdef *>(d_section);
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

    auto r_section = elfMap->findSection(".gnu.version_r");
    if(r_section) {
        auto verneed = elfMap->getSectionReadPtr<ElfXX_Verneed *>(r_section);
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
