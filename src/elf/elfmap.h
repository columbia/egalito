#ifndef EGALITO_ELF_ELFMAP_H
#define EGALITO_ELF_ELFMAP_H

#include <map>
#include <vector>
#include <string>
#include "types.h"

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
    std::vector<void *> findSectionsByType(int type);

    bool hasInterpreter() const { return interpreter != nullptr; }
    const char *getInterpreter() const { return interpreter; }

    size_t getEntryPoint() const;
    bool isExecutable() const;
    bool isSharedLibrary() const;

    char *getCharmap() { return static_cast<char *>(map); }
    int getFileDescriptor() const { return fd; }
    const std::vector<void *> &getSegmentList() const
        { return segmentList; }
};

#endif
