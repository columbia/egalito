#include <cstring>  // for memset
#include "concretedeferred.h"
#include "section.h"
#include "sectionlist.h"
#include "elf/symbol.h"
#include "chunk/function.h"
#include "log/log.h"

SymbolTableContent::DeferredType *SymbolTableContent
    ::add(Function *func, Symbol *sym, size_t strndx) {

    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = static_cast<ElfXX_Word>(strndx);
    symbol->st_info = ELFXX_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = SHN_UNDEF;
    symbol->st_value = func ? func->getAddress() : 0;
    symbol->st_size = func ? func->getSize() : 0;
    auto value = new DeferredType(symbol);
    DeferredMap<Symbol *, ElfXX_Sym>::add(sym, value);
    return value;
}

void SymbolTableContent::add(Symbol *sym, bool atFront) {
    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = 0;
    symbol->st_info = ELFXX_ST_INFO(
        Symbol::bindFromInternalToElf(sym->getBind()),
        Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = sym->getSectionIndex();
    symbol->st_value = 0;
    symbol->st_size = 0;

    auto value = new DeferredType(symbol);
    if(!atFront) {
        DeferredMap<Symbol *, ElfXX_Sym>::add(sym, value);
    }
    else {
        insertAt(this->begin() + 1, sym, value);
    }
}

void SymbolTableContent::add(ElfXX_Sym *symbol) {
    DeferredMap<Symbol *, ElfXX_Sym>::add(nullptr,
        new DeferredType(symbol));
}

ShdrTableContent::DeferredType *ShdrTableContent::add(Section2 *section) {
    auto shdr = new ElfXX_Shdr();
    std::memset(shdr, 0, sizeof(*shdr));

    auto deferred = new DeferredType(shdr);

    LOG(1, "preparing shdr for section [" << section->getName() << "]");

    deferred->addFunction([this, section] (ElfXX_Shdr *shdr) {
        LOG(1, "generating shdr for section [" << section->getName() << "]");
        auto header = section->getHeader();
        shdr->sh_name       = 0;
        shdr->sh_type       = header->getShdrType();
        shdr->sh_flags      = header->getShdrFlags();
        shdr->sh_addr       = header->getAddress();
        shdr->sh_offset     = section->getOffset();
        shdr->sh_size       = section->getContent()->getSize();
        shdr->sh_link       = header->getSectionLink()
            ? header->getSectionLink()->getIndex() : 0;
        shdr->sh_info       = 0;  // updated later for strtabs
        shdr->sh_addralign  = 1;
        shdr->sh_entsize    = 0;
    });

    DeferredMap<Section2 *, ElfXX_Shdr>::add(section, deferred);
    return deferred;
}
