#ifndef EGALITO_GENERATE_SEGMENT_H
#define EGALITO_GENERATE_SEGMENT_H

#include <string>
#include <vector>
#include <elf.h>
#include "types.h"

class Section;

class Segment {
public:
    struct Offset {
        enum OffsetType {ASSIGNABLE, FIXED, ORIGINAL};
        OffsetType type;
        size_t off;
    };
public:
    struct Address {
        enum AddressType {ASSIGNABLE, UNASSIGNABLE, ORIGINAL, FIXED, DEPENDENT};
        AddressType type;
        Segment *dependent;
        address_t addr;
    };
private:
    Address address;
    Offset offset;
    std::vector<Section *> sections;
    bool withPhdr;
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Xword p_align;
public:
    Segment();
    ~Segment();
public:
    Address getAddress() const { return address; }
    Offset getOffset() const { return offset; }
    size_t getSize();
    bool hasPhdr() const { return withPhdr; }
    std::vector<Section *> getSections() const { return sections; }
    Section *getFirstSection() const { return sections[0]; }
    Section *findSection(const std::string &name);
    Elf64_Word getPType() const { return p_type; }
public:
    void setAddress(address_t addr, Address::AddressType type = Address::ASSIGNABLE);
    void setAddressType(Address::AddressType type) {address.type = type;};
    void setOffset(size_t off, Offset::OffsetType type = Offset::ASSIGNABLE);
    void setOffsetType(Offset::OffsetType type) {offset.type = type;};
    void setPhdrInfo(Elf64_Word ptype, Elf64_Word pflags, Elf64_Xword palign);
public:
    friend std::ostream& operator<<(std::ostream &stream, Segment &rhs);
    void add(Section *sec);
    Elf64_Phdr *makePhdr();
};

#endif
