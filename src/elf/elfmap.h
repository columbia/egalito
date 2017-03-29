#ifndef EGALITO_ELF_ELFMAP_H
#define EGALITO_ELF_ELFMAP_H

#include <map>
#include <vector>
#include <string>

#include <elf.h>
#include "types.h"

template <int ELFCLASS>
class ElfType
{
 public:
    typedef typename std::conditional<ELFCLASS == 1, Elf32_Ehdr, Elf64_Ehdr>::type Elf_Ehdr;
};

class ELFGen;

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

    /** 32-bit or 64-bit architecture
     */
    unsigned char archType;
private:
    const char *shstrtab;
    const char *strtab;
    const char *dynstr;
    std::map<std::string, void *> sectionMap;
    std::vector<void *> segmentList;
    const char *interpreter;
private:
    address_t baseAddress;
    address_t copyBase;
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
public:
    void setBaseAddress(address_t base) { baseAddress = base; }
    address_t getBaseAddress() const { return baseAddress; }
    address_t getCopyBaseAddress() const { return copyBase; }
    const char *getStrtab() const { return strtab; }
    const char *getDynstrtab() const { return dynstr; }
    const char *getSHStrtab() const { return shstrtab; }
    void *findSectionHeader(const char *name);
    void *findSection(const char *name);
    //size_t getSectionIndex(const char *name);
    std::vector<void *> findSectionsByType(int type);

    bool hasInterpreter() const { return interpreter != nullptr; }
    const char *getInterpreter() const { return interpreter; }

    size_t getEntryPoint() const;
    bool isExecutable() const;
    bool isSharedLibrary() const;
    bool isDynamic() const { return hasInterpreter(); }

    char *getCharmap() { return static_cast<char *>(map); }
    void *getMap() { return map; }
    int getFileDescriptor() const { return fd; }
    const std::vector<void *> &getSegmentList() const
        { return segmentList; }
private:
    template <typename T>
        size_t getEntryPoint() const {
        auto header = (typename T::Elf_Ehdr*)map;
        return header->e_entry;
    }

    template <typename T>
        bool isExecutable() const {
        auto header = (typename T::Elf_Ehdr*)map;
        return header->e_type == ET_EXEC;
    }

    template <typename T>
        bool isSharedLibrary() const {
        auto header = (typename T::Elf_Ehdr*)map;
        return header->e_type == ET_DYN;
    }

};

#endif
