#include "section.h"
#include "concretesection.h"
#include "elf/symbol.h"
#include "elf/elfxx.h"
#include "chunk/function.h"
#include "log/log.h"

SymbolTableSection::SymbolTableSection(const std::string &name,
    ElfXX_Word type) : Section2(name, type) {

    setContent(new ContentType());
}

void SymbolTableSection::add(Function *func, Symbol *sym, size_t nameStrIndex) {
    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = static_cast<ElfXX_Word>(nameStrIndex);
    symbol->st_info = ELFXX_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = func ? 1 : SHN_UNDEF;  // dynamic symbols have func==nullptr
    symbol->st_value = func ? func->getAddress() : 0;
    symbol->st_size = func ? func->getSize() : 0;
    getContent()->add(sym, symbol);
}

void SymbolTableSection::addAtStart(Symbol *sym) {
    ElfXX_Sym *symbol = new ElfXX_Sym();
    symbol->st_name = 0;
    symbol->st_info = ELFXX_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol->st_other = STV_DEFAULT;
    symbol->st_shndx = sym->getSectionIndex();
    symbol->st_value = 0;
    symbol->st_size = 0;

    getContent()->insertAt(getContent()->begin(), sym, symbol);
}

size_t SymbolTableSection::findIndexWithShIndex(size_t idx) {
#if 0
    size_t index = 0;
    for(auto symbol : getKeyList()) {
        auto value = findValue(symbol);
        if(symbol->getType() == Symbol::TYPE_SECTION
            && value->st_shndx == idx) {

            return index;
        }
        index++;
    }
    return 0;
#else
    size_t index = 0;
    for(auto value : *getContent()) {
        auto key = getContent()->getKey(value);
        if(key->getType() == Symbol::TYPE_SECTION
            && value->st_shndx == idx) {

            return index;
        }
        index ++;
    }
    return 0;
#endif
}

ElfXX_Shdr *SymbolTableSection::makeShdr(size_t index, size_t nameStrIndex) {
    auto shdr = Section::makeShdr(index, nameStrIndex);
    shdr->sh_entsize = sizeof(ElfXX_Sym);
    shdr->sh_info = getCount();
    shdr->sh_addralign = 8;
    return shdr;
}

ElfXX_Shdr *RelocationSection::makeShdr(size_t index, size_t nameStrIndex) {
    auto shdr = Section::makeShdr(index, nameStrIndex);
    shdr->sh_info = sourceSection->getShdrIndex();
    shdr->sh_addralign = 8;
    return shdr;
}

void RelocationSection::commitValues() {
    for(auto value : *this) {
        
    }
}
