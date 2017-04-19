#include "section.h"
#include "elf/symbol.h"
#include "elf/elfxx.h"
#include "chunk/concrete.h"  // for Function
#include "log/log.h"

size_t Section::add(const void *data, size_t size) {
    size_t oldSize = this->data.size();
    add(static_cast<const char *>(data), size);
    return oldSize;
}

size_t Section::add(const char *data, size_t size) {
    size_t oldSize = this->data.size();
    this->data.append(data, size);
    return oldSize;
}

size_t Section::add(const std::string &string, bool withNull) {
    size_t oldSize = this->data.size();
    this->data.append(string.c_str(), string.size() + (withNull ? 1 : 0));
    return oldSize;
}

void Section::addNullBytes(size_t size) {
    this->data.append(size, '\0');
}

ElfXX_Shdr *Section::makeShdr(size_t index, size_t nameStrIndex) {
    this->shdrIndex = index;
    ElfXX_Shdr *entry = new ElfXX_Shdr();
    entry->sh_name = nameStrIndex;
    entry->sh_type = shdrType;
    entry->sh_offset = offset;
    entry->sh_size = getSize();
    entry->sh_addr = address;

    if(shdrType == SHT_SYMTAB || shdrType == SHT_DYNSYM) {
        entry->sh_entsize = sizeof(ElfXX_Sym);
        entry->sh_info = getSize() / entry->sh_entsize;
        entry->sh_addralign = 8;
    }
    else {
        entry->sh_addralign = 1;
    }
    // don't forget to set sh_link!
    return entry;
}

std::ostream& operator<<(std::ostream &stream, Section &rhs) {
    stream << rhs.getData();
    return stream;
}

void SymbolTableSection::add(Function *func, Symbol *sym, size_t nameStrIndex) {
    ElfXX_Sym symbol;
    symbol.st_name = static_cast<ElfXX_Word>(nameStrIndex);
    symbol.st_info = ELFXX_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol.st_other = STV_DEFAULT;
    symbol.st_shndx = func ? 1 : SHN_UNDEF;  // dynamic symbols have func==nullptr
    symbol.st_value = func ? func->getAddress() : 0;
    symbol.st_size = func ? func->getSize() : 0;
    add(static_cast<void *>(&symbol), sizeof(symbol));

    infoMap[sym] = SymbolInfo(count, nameStrIndex);
    count ++;
}

ElfXX_Shdr *SymbolTableSection::makeShdr(size_t index, size_t nameStrIndex) {
    auto shdr = Section::makeShdr(index, nameStrIndex);
    shdr->sh_info = count;
    return shdr;
}

ElfXX_Shdr *RelocationSection::makeShdr(size_t index, size_t nameStrIndex) {
    auto shdr = Section::makeShdr(index, nameStrIndex);
    shdr->sh_info = targetSection->getShdrIndex();
    return shdr;
}

ShdrTableSection::~ShdrTableSection() {
    for(auto shdrPair : shdrPairs)
        delete shdrPair.first;
}

std::ostream& operator<<(std::ostream &stream, ShdrTableSection &rhs) {
    for(auto shdrPair : rhs.getShdrPairs()) {
        rhs.add(shdrPair.first, sizeof(*shdrPair.first));
    }
    stream << rhs.getData();
    return stream;
}
