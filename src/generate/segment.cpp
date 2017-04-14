#include "segment.h"
#include "section.h"
#include "log/registry.h"
#include "log/log.h"

Segment::Segment() : withPhdr(false), p_type(PT_NULL),
    p_flags(PT_NULL), p_align(PT_NULL) {
        address.type = Address::UNASSIGNABLE;
        address.dependent = nullptr;
        address.addr = 0;

        offset.type = Offset::ASSIGNABLE;
        offset.off = 0;
    }

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

void Segment::setOffset(size_t off, Offset::OffsetType type) {
    long int diff = 0;
    for(auto sec : sections) {
        sec->setOffset(off + diff);
        LOG(1, sec->getName() << " @ " << sec->getOffset() << " or " << off);
        diff += sec->getSize();
    }
    offset.type = type;
    offset.off = off;
}

void Segment::setAddress(address_t addr, Address::AddressType type) {
    long int diff = 0;
    for(auto sec : sections) {
        sec->setAddress(address.addr + diff);
        diff += sec->getSize();
    }
    address.type = type;
    address.addr = addr;
}

void Segment::setPhdrInfo(ElfXX_Word ptype, ElfXX_Word pflags, ElfXX_Xword palign) {
    withPhdr = true;
    p_type = ptype;
    p_flags = pflags;
    p_align = palign;
}

void Segment::add(Section *sec) {
    size_t size = getSize();
    sec->setOffset(offset.off + size);
    sec->setAddress(address.addr + size);
    size += sec->getSize();
    sections.push_back(sec);
}

ElfXX_Phdr* Segment::makePhdr() {
    ElfXX_Phdr *entry = new ElfXX_Phdr();
    entry->p_type = p_type;
    entry->p_flags = p_flags;
    entry->p_align = p_align;
    entry->p_offset = offset.off;
    entry->p_vaddr = address.addr;
    entry->p_paddr = entry->p_vaddr;
    entry->p_memsz = getSize();
    entry->p_filesz = entry->p_memsz;
    return entry;
}

std::ostream& operator<<(std::ostream &stream, Segment &rhs) {
    LOG(1, "offset: 0x" << std::hex << rhs.getOffset().off);
    stream.seekp(rhs.getOffset().off);
    for(auto section : rhs.getSections()) {
        stream << *section;
    }
    return stream;
}
