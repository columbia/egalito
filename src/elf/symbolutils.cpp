#include <algorithm>  // for std::sort
#include <cstdio>
#include <sstream>
#include <string.h>
#include <elf.h>
#include "symbol.h"
#include "elfmap.h"
#include "exefile/exemap.h"
#include "elfxx.h"
#include "unionfind.h"

#ifdef USE_WIN64_PE
#include "pe/symbolparser.h"
#endif

#undef DEBUG_GROUP
#define DEBUG_GROUP dsymbol
#include "log/log.h"
#include "log/temp.h"

class SymbolAliasFinder : private UnionFind {
private:
    std::vector<Symbol *> sortedList;

public:
    SymbolAliasFinder(SymbolList *list);

    void constructByAddress();
    Symbol *getSymbol(size_t i) const { return sortedList[i]; }
    size_t getRepresentativeIndex(size_t i) { return find(i); }

private:
    int edgeComparator(size_t x1, size_t x2);
    virtual void setEdge(size_t x1, size_t x2);
};

SymbolClassifier::SymbolClassifier(ExeMap *exeMap)
    : isElf(exeMap->asElf() != nullptr) {}

bool SymbolClassifier::isFunction(Symbol *symbol) const {
    if(isElf) {
#if 0
        LOG(1, "function check for [" << name << "]: type="
            << symbolType
            << ", size=" << size
            << ", index=" << index
            << ", aliasFor=" << (aliasFor ? aliasFor->getName() : "n/a"));
#endif
        if(symbol->getType() == Symbol::TYPE_FUNC
            || symbol->getType() == Symbol::TYPE_IFUNC) {

            return symbol->getSize() > 0
                && symbol->getSectionIndex() > 0
                && !symbol->getAliasFor();
        }
#if 0
        if(symbolType == TYPE_NOTYPE) {
            return shndx != SHN_ABS && !aliasFor;
        }
#endif
    }
    else {
        if(symbol->getType() == Symbol::TYPE_FUNC) {
            return symbol->getSize() > 0 && !symbol->getAliasFor();
        }
    }
    return false;
}

// this may needs to be more strict to handle kernel with assembly files
bool SymbolClassifier::isMarker(Symbol *symbol) const {
    if(isElf) {
        return symbol->getType() == Symbol::TYPE_NOTYPE
            && symbol->getBind() == Symbol::BIND_GLOBAL
            && symbol->getSectionIndex() > 0;
    }
    else {
        return false;
    }
}

SymbolList *SymbolBuilder::buildSymbolList(ElfMap *elfMap,
    std::string symbolFile) {

    if(symbolFile.size() > 0) {
        try {
            // we intentionally do not free this symbolFile; it
            // needs to stay mapped into memory so strings remain valid
            ElfMap *symbolElf = new ElfMap(symbolFile.c_str());
            return buildSymbolList(symbolElf);
        }
        catch(const char *s) {
            // the debug symbol file does not exist
        }
    }

    return buildSymbolList(elfMap);
}

Symbol *SymbolBuilder::findSizeZero(SymbolList *list, const char *sym) {
    auto s = list->find(sym);
    return (s && s->getSize() == 0 ? s : nullptr);
}

static void fixFunctionTypes(SymbolList *list, ElfMap *elfMap) {
#ifdef ARCH_X86_64
    // this may not be correct for ARM; untested
    for(auto sym : *list) {
        if(sym->getType() == Symbol::TYPE_NOTYPE) {
            auto section = elfMap->findSection(sym->getSectionIndex());
            if(!section) continue;

            auto h = section->getHeader();
            if(h->sh_flags & SHF_EXECINSTR) {
                sym->setType(Symbol::TYPE_FUNC);
            }
        }
    }
#endif
}

SymbolList *SymbolBuilder::buildSymbolList(ElfMap *elfMap) {
    auto section = elfMap->findSection(".symtab");
    if(!section || section->getHeader()->sh_type != SHT_SYMTAB) {
        return nullptr;
    }

    auto list = buildAnySymbolList(elfMap, ".symtab", SHT_SYMTAB);
    fixFunctionTypes(list, elfMap);

    if(auto s = findSizeZero(list, "_start")) {
#ifdef ARCH_X86_64
        // s->setSize(42);  // no really! :)
#elif defined(ARCH_AARCH64) || defined(ARCH_ARM)
        // this is harmful since there are two _start()
        //s->setSize(56);  // this does not include embedded following literals
#endif
        s->setType(Symbol::TYPE_FUNC);  // sometimes UNKNOWN
    }
    #ifdef ARCH_RISCV
    if(auto s = list->find("_start")) {
        LOG(1, "Overriding _start size to 54 bytes.");
        s->setSize(54);
    }
    #endif

    if(auto s = list->find("_init")) {  // musl incorrectly sets this to 4
        auto init = elfMap->findSection(".init");
        if(init) s->setSize(init->getHeader()->sh_size);
        if(init) LOG(6, "setting the size of _init to " << init->getHeader()->sh_size);
    }
    if(auto s = list->find("_fini")) {  // musl incorrectly sets this to 4
        auto fini = elfMap->findSection(".fini");
        if(fini) s->setSize(fini->getHeader()->sh_size);
        if(fini) LOG(6, "setting the size of _init to " << fini->getHeader()->sh_size);
    }
    if(auto s = list->find("__init_array_begin")) {
        s->setType(Symbol::TYPE_OBJECT);  // this is really a marker
        s->setSize(8);
    }
    if(auto s = list->find("__init_array_end")) {
        s->setType(Symbol::TYPE_OBJECT);  // this is really a marker
        s->setSize(8);
    }

    if(auto s = list->find("_dl_starting_up")) {
        s->setType(Symbol::TYPE_OBJECT);
        LOG(1, "Found symbol _dl_starting_up");
    }
#if 0
    // for musl only
    if(auto s = list->find("__memcpy_fwd")) {
        s->setType(Symbol::TYPE_FUNC);
    }
    /*if(auto s = list->find("__cp_begin")) {
        s->setType(Symbol::TYPE_FUNC);
    }*/
#endif

    // Fuchsia Zircon script defines a literal
    if(auto s = list->find("buildsig")) {
        s->setSize(0x24);
    }

#if 0
    // for gcc's fentry option (-mfentry)
    if(auto s = list->find("__fentry__")) {
        s->setType(Symbol::TYPE_FUNC);
    }
#endif

#if 0
    // special cases for the Linux kernel
    if(auto s = list->find("startup_64")) {
        s->setType(Symbol::TYPE_FUNC);
        s->setSize(0x30);
    }
    if(auto s = list->find("secondary_startup_64")) {
        s->setType(Symbol::TYPE_FUNC);
    }
#endif

    SymbolAliasFinder aliasFinder(list);
    aliasFinder.constructByAddress();

    for(size_t i = 0; i < list->getCount(); i++) {
        auto rep = aliasFinder.getRepresentativeIndex(i);
        if(rep != i) {
            auto sym = aliasFinder.getSymbol(i);
            auto repSym = aliasFinder.getSymbol(rep);
            sym->setAliasFor(repSym);
            repSym->addAlias(sym);
            LOG(6, "ALIAS: " << std::hex << repSym->getName() << " at address 0x"
                << repSym->getAddress() << " : " << sym->getName()
                << " at address 0x" << sym->getAddress());
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

    for(auto sym : *list) {
        if(sym->getSize() == 0 && sym->getAddress() > 0) {
            size_t estimate = list->estimateSizeOf(sym);
            LOG(5, "estimate size of symbol ["
                << sym->getName() << "] to be " << std::dec << estimate);
            sym->setSize(estimate);
        }
    }

    return list;
}

SymbolList *SymbolBuilder::buildDynamicSymbolList(ElfMap *elfMap) {
    auto list = buildAnySymbolList(elfMap, ".dynsym", SHT_DYNSYM);

    if(auto s = list->find("_init")) {  // musl incorrectly sets this to 4
        if(auto init = elfMap->findSection(".init")) {
            s->setSize(init->getHeader()->sh_size);
            LOG(6, "setting the size of _init to "
                << init->getHeader()->sh_size);
        }
    }
    if(auto s = list->find("_fini")) {  // musl incorrectly sets this to 4
        if(auto fini = elfMap->findSection(".fini")) {
            s->setSize(fini->getHeader()->sh_size);
            LOG(6, "setting the size of _init to "
                << fini->getHeader()->sh_size);
        }
    }

    //TemporaryLogLevel tll("dsymbol", 10);
    SymbolVersionList versionList(elfMap);
    for(auto sym : *list) {
        auto index = sym->getIndex();
        auto verName = versionList.getVersionName(index);
        bool verHidden = versionList.isHidden(index);

        LOG(10, "symbol " << sym->getName() << " has version " << verName
            << " hidden? " << verHidden);
        sym->setVersion(new SymbolVersion(verName, verHidden));
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
            LOG(6, "dynsym ALIAS: " << std::hex << repSym->getName() << " at address 0x"
                << repSym->getAddress() << " : " << sym->getName()
                << " at address 0x" << sym->getAddress());
        }
    }

    return list;
}

SymbolList *SymbolBuilder::buildAnySymbolList(ElfMap *elfMap,
    const char *sectionName, unsigned sectionType) {

#if defined(ARCH_AARCH64) || defined(ARCH_ARM)
    // mapping symbols indicate inline data in code section on arm
    SymbolList *list = new SymbolListWithMapping(elfMap);
#else
    SymbolList *list = new SymbolList(elfMap);
#endif

    auto section = elfMap->findSection(sectionName);
    if(!section || section->getHeader()->sh_type != sectionType) {
        LOG(1, "Warning: no symbol table " << sectionName << " in ELF file");
        return list;
    }

    const char *strtab = (sectionType == SHT_DYNSYM
        ? elfMap->getDynstrtab() : elfMap->getStrtab());

    auto sym = elfMap->getSectionReadPtr<ElfXX_Sym *>(section);
    auto s = section->getHeader();
    int symcount = s->sh_size / s->sh_entsize;
    for(int j = 0; j < symcount; j ++, sym ++) {
        auto type = typeFromElfToInternal(sym->st_info);
        auto bind = bindFromElfToInternal(sym->st_info);

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

        if(elfMap->isObjectFile()) {
            LOG0(5, "symbol name: " << sym->st_name << " shndx " << shndx);
            auto symSection = elfMap->findSection(shndx);
            // will be null if COM section...
            if(symSection) {
                // Convert Offset to Virtual address.
                address += symSection->getVirtualAddress();
            }
        }

        Symbol *symbol = new Symbol(address, size, name, type, bind, j, shndx);
        CLOG0(5, "%s symbol #%d, index %d, [%s] %lx, type %d\n", sectionName,
            (int)list->getCount(), j, name, address, type);
        list->add(symbol, (size_t)j);
    }

    list->buildMappingList();
    return list;
}

unsigned char SymbolBuilder::typeFromInternalToElf(Symbol::SymbolType type) {
    switch(type) {
    case Symbol::TYPE_FUNC:     return STT_FUNC;
    case Symbol::TYPE_IFUNC:    return STT_GNU_IFUNC;
    case Symbol::TYPE_OBJECT:   return STT_OBJECT;
    case Symbol::TYPE_SECTION:  return STT_SECTION;
    case Symbol::TYPE_FILE:     return STT_FILE;
    case Symbol::TYPE_TLS:      return STT_TLS;
    default:                    return STT_NOTYPE;
    }
}

Symbol::SymbolType SymbolBuilder::typeFromElfToInternal(unsigned char type) {
    switch(ELFXX_ST_TYPE(type)) {
    case STT_FUNC:     return Symbol::TYPE_FUNC;
    case STT_GNU_IFUNC:return Symbol::TYPE_IFUNC;
    case STT_OBJECT:   return Symbol::TYPE_OBJECT;
    case STT_SECTION:  return Symbol::TYPE_SECTION;
    case STT_FILE:     return Symbol::TYPE_FILE;
    case STT_TLS:      return Symbol::TYPE_TLS;
    case STT_NOTYPE:   return Symbol::TYPE_NOTYPE;
    default:           return Symbol::TYPE_UNKNOWN;
    }
}

unsigned char SymbolBuilder::bindFromInternalToElf(Symbol::BindingType bind) {
    switch(bind) {
    case Symbol::BIND_LOCAL:  return STB_LOCAL;
    case Symbol::BIND_GLOBAL: return STB_GLOBAL;
    default:                  return STB_WEAK;
    }
}

Symbol::BindingType SymbolBuilder::bindFromElfToInternal(unsigned char type) {
    switch(ELFXX_ST_BIND(type)) {
    case STB_LOCAL:     return Symbol::BIND_LOCAL;
    case STB_GLOBAL:    return Symbol::BIND_GLOBAL;
    default:            return Symbol::BIND_WEAK;
    }
}

SymbolAliasFinder::SymbolAliasFinder(SymbolList *list)
    : UnionFind(list->getCount()), sortedList(list->begin(), list->end()) {
    std::sort(sortedList.begin(), sortedList.end(),
        [](Symbol *a, Symbol *b) {
            return a->getAddress() < b->getAddress();
        });
}

// Returning -1 means set parent[x1] = x2;
// returning +1 means set parent[x2] = x1.
int SymbolAliasFinder::edgeComparator(size_t x1, size_t x2) {
    auto s1 = sortedList[x1];
    auto s2 = sortedList[x2];

    // section vs others
    if(s1->getType() != s2->getType()) {
        if(s1->getType() == Symbol::TYPE_SECTION) return -1;
        if(s2->getType() == Symbol::TYPE_SECTION) return +1;
        if(s1->getType() == Symbol::TYPE_FILE) return -1;
        if(s2->getType() == Symbol::TYPE_FILE) return +1;
    }

    // normal symbol > mapping symbol
    // mapping symbol names shouldn't be used at all
    if(s1->getBind() == Symbol::BIND_LOCAL && s1->getName()[0] == '$') return -1;
    if(s2->getBind() == Symbol::BIND_LOCAL && s2->getName()[0] == '$') return +1;

    // this seems to be a good heuristic
    if(strstr(s1->getName(), s2->getName())) return -1;
    if(strstr(s2->getName(), s1->getName())) return +1;

    // treat single "@" as canonical over double "@@"
    if(strstr(s1->getName(), "@@")) return +1;
    if(strstr(s2->getName(), "@@")) return -1;
    if(strstr(s1->getName(), "@")) return -1;
    if(strstr(s2->getName(), "@")) return +1;

    if(s1->getBind() != s2->getBind()) {
        // weak symbols are the symbols that are usually used
        if(s1->getBind() == Symbol::BIND_LOCAL) return -1;
        if(s2->getBind() == Symbol::BIND_LOCAL) return +1;
        if(s1->getBind() == Symbol::BIND_GLOBAL) return +1;
        if(s2->getBind() == Symbol::BIND_GLOBAL) return -1;
        if(s1->getBind() == Symbol::BIND_WEAK) return +1;
        if(s2->getBind() == Symbol::BIND_WEAK) return -1;
    }

    if(s1->getSize() != s2->getSize()) {
        if(s1->getSize() == 0) return -1;
        if(s2->getSize() == 0) return +1;
    }

    // we might need a DB of standard API names
    LOG(5, "setting an alias ARBITRARILY ("
        << s2->getName() << "->" << s1->getName() << ")");
    return -1;
}

void SymbolAliasFinder::setEdge(size_t x1, size_t x2) {
    int comparator = edgeComparator(x1, x2);

    if(comparator < 0) {
        parent[x1] = x2;
    }
    else if(comparator > 0) {
        parent[x2] = x1;
    }
    else {
        LOG(1, "WARNING: attempting to alias nearly identical symbols, skipping");
    }
}

void SymbolAliasFinder::constructByAddress() {
    for(size_t i = 0; i < sortedList.size(); i++) {
        auto sym = sortedList[i];
        //if(sym->getSectionIndex() == SHN_UNDEF) continue;
        //if(sym->getType() == Symbol::TYPE_SECTION) continue;
        if(sym->getType() == Symbol::TYPE_FILE) continue;

        for(size_t j = i + 1; j < sortedList.size(); j++) {
            auto sym2 = sortedList[j];
            if(sym->getAddress() != sym2->getAddress()) {
                break;
            }
            /* if(sym2->getSectionIndex() == SHN_UNDEF) continue; */
            //if(sym2->getType() == Symbol::TYPE_SECTION) continue;
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
