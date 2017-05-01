#ifndef EGALITO_GENERATE_SECTION_H
#define EGALITO_GENERATE_SECTION_H

#include <algorithm>  // for std::find
#include <string>
#include <vector>
#include <map>
#include <elf.h>
#include "elf/elfxx.h"
#include "deferred.h"
#include "types.h"

class SectionRef;
class Section;

class SectionHeader {
private:
    Section *outer;  // ptr so that we can fetch content size
private:
    address_t address;
    ElfXX_Word shdrType;
    ElfXX_Xword shdrFlags;
    SectionRef *sectionLink;
public:
    SectionHeader(Section *outer, ElfXX_Word type,
        ElfXX_Xword flags = 0);

    address_t getAddress() const { return address; }
    ElfXX_Word getShdrType() const { return shdrType; }
    ElfXX_Xword getShdrFlags() const { return shdrFlags; }
    SectionRef *getSectionLink() const { return sectionLink; }

    void setAddress(address_t addr) { address = addr; }
    void setShdrFlags(ElfXX_Xword flags) { shdrFlags = flags; }
    void setSectionLink(SectionRef *link) { sectionLink = link; }

    size_t getSize() const { return sizeof(ElfXX_Shdr); }
};

class Section {
private:
    std::string name;
    size_t offset;
    SectionHeader *header;
    DeferredValue *content;
public:
    /** Constructs a Section which will be mapped into memory. */
    Section(const std::string &name, ElfXX_Word type, ElfXX_Xword flags = 0);
    /** Constructs an ephemeral Section which is not mapped into memory. */
    Section(const std::string &name, DeferredValue *content = nullptr);
    virtual ~Section() { delete header, delete content; }

    const std::string &getName() const { return name; }
    size_t getOffset() const { return offset; }
    void setOffset(size_t off) { offset = off; }

    SectionHeader *getHeader() const { return header; }
    DeferredValue *getContent() const { return content; }
    bool hasHeader() const { return header != nullptr; }
    bool hasContent() const { return content != nullptr; }
    void setHeader(SectionHeader *header) { this->header = header; }
    void setContent(DeferredValue *content) { this->content = content; }

    template <typename ValueType>
    ValueType castAs() { return dynamic_cast<ValueType>(content); }

    template <typename ValueType>
    ValueType castAsValue() { return dynamic_cast<
        DeferredValueImpl<ValueType>>(content)->getElfPtr(); }

    template <typename ValueType>
    DeferredList<ValueType> *contentAsList()
        { return dynamic_cast<DeferredList<ValueType> *>(content); }

    template <typename KeyType, typename ValueType>
    DeferredMap<KeyType, ValueType> *contentAsMap()
        { return dynamic_cast<DeferredMap<KeyType, ValueType> *>(content); }

    DeferredStringList *contentAsStringList()
        { return dynamic_cast<DeferredStringList *>(content); }
};

std::ostream &operator << (std::ostream &stream, Section &rhs);

#endif
