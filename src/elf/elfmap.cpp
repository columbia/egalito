#include <iostream>
#include <sstream>
#include "elfmap.h"
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

ElfMap::ElfMap(pid_t pid) {
    std::ostringstream stream;
    stream << "/proc/" << static_cast<int>(pid) << "/exe";
    parseElf(stream.str().c_str());
    setup();
}

ElfMap::ElfMap(const char *filename) {
    parseElf(filename);
    setup();
}

ElfMap::ElfMap(void *self) : map(self), length(0), fd(-1) {
    setup();
}

ElfMap::~ElfMap() {
    if(length) munmap(map, length);
    if(fd > 0) close(fd);
}

void ElfMap::setup() {
    verifyElf();
    makeSectionMap();
    makeSegmentList();
}

void ElfMap::parseElf(const char *filename) {
    fd = open(filename, O_RDONLY, 0);
    if(fd < 0) throw "can't open executable image\n";
    
    // find the length of the file
    length = static_cast<size_t>(lseek(fd, 0, SEEK_END));
    lseek(fd, 0, SEEK_SET);
    
    // make a private copy of the file in memory
    int prot = PROT_READ /*| PROT_WRITE*/;
    map = mmap(NULL, length, prot, MAP_PRIVATE, fd, 0);
    if(map == (void *)-1) throw "can't mmap executable image\n";
    
    verifyElf();
}

void ElfMap::verifyElf() {
    // make sure this is an ELF file
    if(*(Elf64_Word *)map != *(Elf64_Word *)ELFMAG) {
        throw "executable image does not have ELF magic\n";
    }
    
    // check architecture type
    char type = ((char *)map)[EI_CLASS];
    if(type != ELFCLASS64) {
        throw "file is not 64-bit ELF, unsupported\n";
    }
}

void ElfMap::makeSectionMap() {
    char *charmap = static_cast<char *>(map);
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;
    if(sizeof(Elf64_Shdr) != header->e_shentsize) {
        throw "header shentsize mismatch\n";
    }
    
    Elf64_Shdr *sheader = (Elf64_Shdr *)(charmap + header->e_shoff);
    //Elf64_Phdr *pheader = (Elf64_Phdr *)(charmap + header->e_phoff);

    this->shstrtab = charmap + sheader[header->e_shstrndx].sh_offset;

    for(int i = 0; i < header->e_shnum; i ++) {
        Elf64_Shdr *s = &sheader[i];
        const char *name = shstrtab + s->sh_name;

        //std::cout << "section [" << name << "]\n";

        sectionMap[name] = static_cast<void *>(s);
    }

    this->strtab = static_cast<const char *>(findSection(".strtab"));
    this->dynstr = static_cast<const char *>(findSection(".dynstr"));
}

void ElfMap::makeSegmentList() {
    // this also calculates copyBase

    char *charmap = static_cast<char *>(map);
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;
    Elf64_Phdr *pheader = (Elf64_Phdr *)(charmap + header->e_phoff);
    for(int i = 0; i < header->e_phnum; i ++) {
        Elf64_Phdr *phdr = &pheader[i];

        segmentList.push_back(static_cast<void *>(phdr));

        if(phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X)) {
            copyBase = (address_t)(charmap + phdr->p_offset - phdr->p_vaddr);
        }
    }
}

void *ElfMap::findSectionHeader(const char *name) {
    auto it = sectionMap.find(name);
    if(it == sectionMap.end()) return nullptr;

    return (*it).second;
}

void *ElfMap::findSection(const char *name) {
    auto it = sectionMap.find(name);
    if(it == sectionMap.end()) return nullptr;

    char *charmap = static_cast<char *>(map);
    auto shdr = static_cast<Elf64_Shdr *>((*it).second);
    return static_cast<void *>(charmap + shdr->sh_offset);
}

std::vector<void *> ElfMap::findSectionsByType(int type) {
    std::vector<void *> sections;

    char *charmap = static_cast<char *>(map);
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;
    Elf64_Shdr *sheader = (Elf64_Shdr *)(charmap + header->e_shoff);
    for(int i = 0; i < header->e_shnum; i ++) {
        Elf64_Shdr *s = &sheader[i];

        if(s->sh_type == static_cast<uint32_t>(type)) {
            sections.push_back(static_cast<void *>(s));
        }
    }

    return std::move(sections);
}

size_t ElfMap::getEntryPoint() const {
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;
    return header->e_entry;
}

bool ElfMap::isExecutable() const {
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;
    return header->e_type == ET_EXEC;
}

bool ElfMap::isSharedLibrary() const {
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;
    return header->e_type == ET_DYN;
}

address_t *ElfMap::findAuxV(char **argv) {
    address_t *address = reinterpret_cast<address_t *>(argv);
    
    //address ++;  // skip argc
    while(*address++) {}  // skip argv entries
    while(*address++) {}  // skip envp entries
    
    return address;
}


void ElfMap::adjustAuxV(char **argv, address_t baseAddress,
    bool isInterp) {

    address_t *auxv = findAuxV(argv);
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;

    std::cout << "Fixing auxiliary vector\n";

    // Loop through all auxiliary vector entries, stopping at the terminating
    // entry of type AT_NULL.
    for(address_t *p = auxv; p[0] != AT_NULL; p += 2) {
        address_t type = p[0];
        address_t *new_value = &p[1];
        if(isInterp) {
            switch(type) {
            case AT_BASE:
                // *new_value = baseAddress;
                *new_value = reinterpret_cast<address_t>(map);
                std::printf("AUXV: Base address: 0x%lx\n", *new_value);
                break;
            case AT_ENTRY:
                *new_value = baseAddress + header->e_entry;
                std::printf("AUXV: Entry point: 0x%lx\n", *new_value);
                break;
            default:
                break;
            }
        }
        else {
            switch(type) {
            case AT_PHDR:
                *new_value = reinterpret_cast<address_t>(map) + header->e_phoff;
                // *new_value = baseAddress + header->e_phoff;
                break;
            case AT_PHENT:
                *new_value = header->e_phentsize;
                break;
            case AT_PHNUM:
                *new_value = header->e_phnum;
                break;
            case AT_EXECFN:
                static const char *fakeFilename
                    //= "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
                    = "./hello";
                std::printf("AUXV: old exec filename is [%s]\n",
                    reinterpret_cast<char *>(*new_value));
                *new_value = reinterpret_cast<address_t>(fakeFilename);
                std::printf("AUXV: new exec filename is [%s]\n",
                    reinterpret_cast<char *>(*new_value));
                break;
            default:
                break;
            }
        }
    }
}
