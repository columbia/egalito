#ifndef EGALITO_ELF_ELFMAP_H
#define EGALITO_ELF_ELFMAP_H

#include <map>
#include <vector>
#include <string>
#include "types.h"
#include <elf.h>
#include "elfxx.h"

class ELFGen;
class ElfSection {
private:
    int ndx;
    std::string name;
    ElfXX_Shdr *shdr;
    address_t virtualAddress;
    address_t readAddress;
public:
    ElfSection(int ndx, std::string name, ElfXX_Shdr *shdr)
        : ndx(ndx), name(name), shdr(shdr), virtualAddress(0), readAddress(0) {}

    int getNdx() { return ndx; }
    std::string getName() { return name; }
    ElfXX_Shdr *getHeader() { return shdr; }
    address_t getVirtualAddress() { return virtualAddress; }
    address_t getReadAddress() { return readAddress; }
    void setVirtualAddress(address_t address) { virtualAddress = address; }
    void setReadAddress(address_t address) { readAddress = address; }
    address_t convertOffsetToVA(size_t offset);
    address_t convertVAToOffset(address_t va);
    size_t getSize() const { return shdr->sh_size; }
    size_t getAlignment() const { return shdr->sh_addralign; }
};

class ElfMap {
    friend class ELFGen;
private:
    /** Memory map of executable image.
    */
    void *map;

    /** Size of memory map.
    */
    size_t length;

    /** File descriptor associated with memory map.
    */
    int fd;
private:
    const char *shstrtab;
    const char *strtab;
    const char *dynstr;
    std::map<std::string, ElfSection *> sectionMap;
    std::vector<ElfSection *> sectionList;
    std::vector<void *> segmentList;
    const char *interpreter;
private:
    address_t baseAddress;
    address_t copyBase;
    address_t rwCopyBase;
public:
    ElfMap(pid_t pid);
    ElfMap(const char *filename);
    ElfMap(void *self);
    ~ElfMap();
private:
    void setup();
    void parseElf(const char *filename);
    void verifyElf();
    void makeSectionMap();
    void makeSegmentList();
    void makeVirtualAddresses();
public:
    void setBaseAddress(address_t base) { baseAddress = base; }
    address_t getBaseAddress() const { return baseAddress; }
    address_t getCopyBaseAddress() const { return copyBase; }
    address_t getRWCopyBaseAddress() const { return rwCopyBase; }
    size_t getLength() const { return length; }
    const char *getStrtab() const { return strtab; }
    const char *getDynstrtab() const { return dynstr; }
    const char *getSHStrtab() const { return shstrtab; }

    ElfSection *findSection(const char *name) const;
    ElfSection *findSection(int index) const;
    template <typename T>
    T getSectionReadPtr(ElfSection *section);
    template <typename T>
    T getSectionReadPtr(int index);
    template <typename T>
    T getSectionReadPtr(const char *name);

    std::vector<void *> findSectionsByType(int type);
    std::vector<void *> findSectionsByFlag(long flag);

    bool hasInterpreter() const { return interpreter != nullptr; }
    const char *getInterpreter() const { return interpreter; }

    size_t getEntryPoint() const;
    bool isExecutable() const;
    bool isSharedLibrary() const;
    bool isObjectFile() const;
    bool isDynamic() const;
    bool hasRelocations() const;

    char *getCharmap() { return static_cast<char *>(map); }
    void *getMap() { return map; }
    int getFileDescriptor() const { return fd; }
    const std::vector<void *> &getSegmentList() const
        { return segmentList; }
};

template <typename T>
T ElfMap::getSectionReadPtr(ElfSection *section) {
    return reinterpret_cast<T>(section->getReadAddress());
}

template <typename T>
T ElfMap::getSectionReadPtr(int index) {
    ElfSection *section = findSection(index);
    if (!section) return static_cast<T>(0);

    return reinterpret_cast<T>(section->getReadAddress());
}

template <typename T>
T ElfMap::getSectionReadPtr(const char *name) {
    auto section = findSection(name);
    if (!section) return static_cast<T>(0);

    return getSectionReadPtr<T>(section);
}

#endif
