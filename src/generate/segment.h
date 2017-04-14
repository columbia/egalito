#ifndef EGALITO_GENERATE_SEGMENT_H
#define EGALITO_GENERATE_SEGMENT_H

#include <string>
#include <vector>
#include <elf.h>
#include "elf/elfmap.h"
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
    ElfXX_Word p_type;
    ElfXX_Word p_flags;
    ElfXX_Xword p_align;
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
    ElfXX_Word getPType() const { return p_type; }
public:
    void setAddress(address_t addr, Address::AddressType type = Address::ASSIGNABLE);
    void setAddressType(Address::AddressType type, Segment *seg = nullptr) {
        address.type = type;
        address.dependent = seg;
    }
    void setOffset(size_t off, Offset::OffsetType type = Offset::ASSIGNABLE);
    void setOffsetType(Offset::OffsetType type) {offset.type = type;};
    void setPhdrInfo(ElfXX_Word ptype, ElfXX_Word pflags, ElfXX_Xword palign);
public:
    friend std::ostream& operator<<(std::ostream &stream, Segment &rhs);
    void add(Section *sec);
    ElfXX_Phdr *makePhdr();
};

#endif
