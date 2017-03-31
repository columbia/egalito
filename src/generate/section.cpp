#include "section.h"
#include "elf/symbol.h"
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

Elf64_Shdr *Section::makeShdr(size_t index, size_t nameStrIndex) {
    this->shdrIndex = index;
    Elf64_Shdr *entry = new Elf64_Shdr();
    entry->sh_name = nameStrIndex;
    entry->sh_type = shdrType;
    entry->sh_offset = fileOffset;
    entry->sh_size = getSize();
    entry->sh_addr = address;

    if(shdrType == SHT_SYMTAB) {
        entry->sh_entsize = sizeof(Elf64_Sym);
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
    Elf64_Sym symbol;
    symbol.st_name = static_cast<Elf64_Word>(nameStrIndex);
    symbol.st_info = ELF64_ST_INFO(Symbol::bindFromInternalToElf(sym->getBind()),
                                   Symbol::typeFromInternalToElf(sym->getType()));
    symbol.st_other = STV_DEFAULT;
    symbol.st_shndx = func ? 1 : 3;  // dynamic symbols have func==nullptr
    symbol.st_value = func ? func->getAddress() : 0;
    symbol.st_size = func ? func->getSize() : 0;
    add(static_cast<void *>(&symbol), sizeof(symbol));
    count ++;
    LOG(1, "add -> " << count);
}

Elf64_Shdr *SymbolTableSection::makeShdr(size_t index, size_t nameStrIndex) {
    auto shdr = Section::makeShdr(index, nameStrIndex);
    LOG(1, "set sh_info to " << count);
    shdr->sh_info = count;
    return shdr;
}
