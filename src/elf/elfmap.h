#ifndef EGALITO_ELF_ELFMAP_H
#define EGALITO_ELF_ELFMAP_H

#include <map>
#include <string>

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
};

#endif
