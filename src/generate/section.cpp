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
    LOG(1, "    really added " << size << " bytes");
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
    entry->sh_flags = shdrFlags;
    entry->sh_offset = offset;
    entry->sh_size = getSize();
    entry->sh_addr = address;

    if(shdrType == SHT_SYMTAB || shdrType == SHT_DYNSYM) {
        entry->sh_entsize = sizeof(ElfXX_Sym);
        entry->sh_info = getSize() / entry->sh_entsize;
        entry->sh_addralign = 8;
    } else if(shdrType == SHT_RELA) {
        entry->sh_entsize = sizeof(ElfXX_Rela);
        entry->sh_addralign = 8;
    } else {
        entry->sh_entsize = 0;
        entry->sh_info = 0;  // updated later for strtabs
        entry->sh_addralign = 1;
    }
    // don't forget to set sh_link!
    return entry;
}

std::ostream& operator<<(std::ostream &stream, Section &rhs) {
    rhs.commitContents();
    auto data = rhs.getData();
    stream << data;
    LOG(1, "actual size " << data.size());
    return stream;
}
