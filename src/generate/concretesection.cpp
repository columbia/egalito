#include "section.h"
#include "concretesection.h"
#include "elf/symbol.h"
#include "elf/elfxx.h"
#include "chunk/function.h"
#include "log/log.h"

void SymbolTableSection::add(Function *func, Symbol *sym, size_t nameStrIndex) {
    ElfXX_Sym symbol;
    symbol.st_name = static_cast<ElfXX_Word>(nameStrIndex);
    symbol.st_info = ELFXX_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol.st_other = STV_DEFAULT;
    symbol.st_shndx = func ? 1 : SHN_UNDEF;  // dynamic symbols have func==nullptr
    symbol.st_value = func ? func->getAddress() : 0;
    symbol.st_size = func ? func->getSize() : 0;
    addElement(sym, symbol);
}

ElfXX_Shdr *SymbolTableSection::makeShdr(size_t index, size_t nameStrIndex) {
    auto shdr = Section::makeShdr(index, nameStrIndex);
    shdr->sh_info = getCount();
    return shdr;
}

ElfXX_Shdr *RelocationSection::makeShdr(size_t index, size_t nameStrIndex) {
    auto shdr = Section::makeShdr(index, nameStrIndex);
    shdr->sh_info = targetSection->getShdrIndex();
    return shdr;
}

void ShdrTableSection::commitContents() {
    for(auto element : getContentList()) {
        auto content = findContent(element);
        LOG(1, "add " << sizeof(*content) << " bytes");
        add(static_cast<void *>(content), sizeof(*content));
    }
}
