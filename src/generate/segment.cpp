#include "segment.h"
#include "section.h"
#include "log/registry.h"
#include "log/log.h"

Segment::~Segment() {
    for(auto s : sections)
        delete s;
}
size_t Segment::getSize() {
    size_t size = 0;
    for(auto sec : sections) {
        size += sec->getSize();
    }
    return size;
}

Section *Segment::findSection(const std::string &name) {
    for(auto sec : sections) {
        if(sec->getName() == name) return sec;
    }
    return nullptr;
}

void Segment::setFileOff(size_t offset) {
    long int diff = 0;
    for(auto sec : sections) {
        sec->setFileOff(offset + diff);
        diff += sec->getSize();
    }
    fileOffset = offset;
}

void Segment::setAddress(address_t addr) {
    long int diff = 0;
    for(auto sec : sections) {
        sec->setAddress(addr + diff);
        diff += sec->getSize();
    }
    address = addr;
}

void Segment::setPhdrInfo(Elf64_Word ptype, Elf64_Word pflags, Elf64_Xword palign) {
    p_type = ptype;
    p_flags = pflags;
    p_align = palign;
}

void Segment::add(Section *sec) {
    size_t size = getSize();
    sec->setFileOff(fileOffset + size);
    sec->setAddress(address + size);
    size += sec->getSize();
    sections.push_back(sec);
}

Elf64_Phdr* Segment::makePhdr() {
    Elf64_Phdr *entry = new Elf64_Phdr();
    entry->p_type = p_type;
    entry->p_flags = p_flags;
    entry->p_align = p_align;
    entry->p_offset = fileOffset;
    entry->p_vaddr = address;
    entry->p_paddr = entry->p_vaddr;
    entry->p_memsz = getSize();
    entry->p_filesz = entry->p_memsz;
    return entry;
}

std::ostream& operator<<(std::ostream &stream, Segment &rhs) {
    LOG(1, "offset: 0x" << std::hex << rhs.getFileOff());
    stream.seekp(rhs.getFileOff());
    for(auto section : rhs.getSections()) {
        stream << *section;
    }
    return stream;
}
