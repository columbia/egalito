#ifndef EGALITO_GENERATE_SECTION_H
#define EGALITO_GENERATE_SECTION_H

#include <string>
#include <set>
#include <elf.h>
#include "types.h"

class Section {
private:
    std::string data;
    std::string name;
    address_t address;
    size_t fileOffset;
    bool withShdr;
    Elf64_Word shdrType;
    Section *sectionLink;
    size_t shdrIndex;
public:
    Section(std::string name, bool withShdr = true) : name(name),
        address(0), fileOffset(0), withShdr(withShdr), shdrType(SHT_NULL) {}
    Section(std::string name, const void *data, size_t size, bool withShdr = true) : name(name),
        address(0), fileOffset(0), withShdr(withShdr), shdrType(SHT_NULL)
        { add(data, size); }
public:
    std::string getData() const { return data; }
    std::string getName() const { return name; }
    address_t getAddress() const { return address; }
    size_t getFileOff() const { return fileOffset; }
    size_t getSize() const { return data.size(); }
    bool hasShdr() const { return withShdr; }
    Section *getSectionLink() const { return sectionLink; }
    size_t getShdrIndex() const { return shdrIndex; }
public:
    void setAddress(address_t addr) { address = addr; }
    void setFileOff(size_t offset) { fileOffset = offset; }
    void setSectionLink(Section *link) { sectionLink = link; }
    void setShdrType(Elf64_Word type) { shdrType = type; }
public:
    friend std::ostream& operator<<(std::ostream &stream, Section &rhs);
    void add(const void *data, size_t size);
    void add(const char *data, size_t size);
    Elf64_Shdr *makeShdr(size_t index);
    template<typename ElfStructType> ElfStructType *castAs()
        { return (ElfStructType *)(data.data()); }
    template<typename ElfStructType> size_t getElementCount()
        { return data.size() / sizeof(ElfStructType); }
};

#endif
