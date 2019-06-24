#ifndef EGALITO_ELF_ELFMAP_H
#define EGALITO_ELF_ELFMAP_H

#include <map>
#include <vector>
#include <string>
#include "types.h"
#include <elf.h>
#include "elfxx.h"
#include "exefile/exemap.h"

class ElfSection : public ExeSectionImpl {
private:
    int ndx;
    std::string name;
    ElfXX_Shdr *shdr;
    address_t virtualAddress;
    address_t readAddress;
public:
    ElfSection(int index, const std::string &name, ElfXX_Shdr *shdr)
        : ExeSectionImpl(index, name), shdr(shdr) {}

    ElfXX_Shdr *getHeader() { return shdr; }
    virtual size_t getSize() const { return shdr->sh_size; }
    size_t getAlignment() const { return shdr->sh_addralign; }

    virtual bool isExecutable() const
        { return (shdr->sh_flags & SHF_EXECINSTR); }
};

class ElfMap : public ExeMapImpl<ElfSection> {
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
    std::vector<void *> segmentList;
    const char *interpreter;
private:
    //address_t baseAddress;
    address_t copyBase;     // base for RX segment
    address_t rwCopyBase;   // base for RW segment
private:
    ElfMap();
public:
    ElfMap(pid_t pid);
    ElfMap(const char *filename);
    ElfMap(void *self);
    ~ElfMap();
    static bool isElf(const char *filename);
private:
    void setup();
    void parseElf(const char *filename);
    void verifyElf();
    void makeSectionMap();
    void makeSegmentList();
    void makeVirtualAddresses();
public:
    address_t getCopyBaseAddress() const { return copyBase; }
    address_t getRWCopyBaseAddress() const { return rwCopyBase; }
    size_t getLength() const { return length; }
    const char *getStrtab() const { return strtab; }
    const char *getDynstrtab() const { return dynstr; }
    const char *getSHStrtab() const { return shstrtab; }

    std::vector<void *> findSectionsByType(int type) const;
    std::vector<void *> findSectionsByFlag(long flag) const;

    bool hasInterpreter() const { return interpreter != nullptr; }
    const char *getInterpreter() const { return interpreter; }

    virtual size_t getEntryPoint() const;
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

#endif
