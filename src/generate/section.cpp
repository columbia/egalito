#include "section.h"

void Section::add(const void *data, size_t size) {
    add(static_cast<const char *>(data), size);
}

void Section::add(const char *data, size_t size) {
    this->data.append(data, size);
}

Elf64_Shdr *Section::makeShdr(size_t index) {
    this->shdrIndex = index;
    Elf64_Shdr *entry = new Elf64_Shdr();
    // entry->sh_name = data.getShdrListSize(); // HERE
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
