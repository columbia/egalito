#ifndef EGALITO_ELF_ELFMAP_H
#define EGALITO_ELF_ELFMAP_H

#include <map>
#include <vector>
#include <string>
#include "types.h"

class ElfMap {
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
private:
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
    address_t getBaseAddress() const { return 0; }
    address_t getCopyBaseAddress() const { return copyBase; }
    const char *getStrtab() const { return strtab; }
    const char *getDynstrtab() const { return dynstr; }
    void *findSectionHeader(const char *name);
    void *findSection(const char *name);

    size_t getEntryPoint() const;

    int getFileDescriptor() const { return fd; }
    const std::vector<void *> &getSegmentList() const
        { return segmentList; }
};

#endif
