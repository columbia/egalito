#include <iostream>
#include <sstream>

#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include "elfmap.h"
#include "log/log.h"

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
    CLOG(1, "creating ElfMap for file [%s]", filename);
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

    unsigned char *e_ident = ((Elf32_Ehdr *)map)->e_ident;
    if (   e_ident[EI_MAG0] != ELFMAG0
        || e_ident[EI_MAG1] != ELFMAG1
        || e_ident[EI_MAG2] != ELFMAG2
        || e_ident[EI_MAG3] != ELFMAG3) {
        throw "executable image does not have ELF magic\n";
    }

    // check architecture type
    unsigned char type = e_ident[EI_CLASS];

    if (type != ELFCLASS32 && type != ELFCLASS64) {
        throw "file is not 32-bit or 64-bit ELF, unsupported\n";
    }

    this->archType = type;
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
        LOG(1, "found section [" << name << "] in elf file");
    }

    this->strtab = static_cast<const char *>(findSection(".strtab"));
    this->dynstr = static_cast<const char *>(findSection(".dynstr"));
}

void ElfMap::makeSegmentList() {
    // this also calculates copyBase and sets interpreter
    baseAddress = 0;
    copyBase = 0;
    interpreter = nullptr;

    char *charmap = static_cast<char *>(map);
    Elf64_Ehdr *header = (Elf64_Ehdr *)map;
    Elf64_Phdr *pheader = (Elf64_Phdr *)(charmap + header->e_phoff);
    for(int i = 0; i < header->e_phnum; i ++) {
        Elf64_Phdr *phdr = &pheader[i];

        segmentList.push_back(static_cast<void *>(phdr));

        if(phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X)) {
            copyBase = (address_t)(charmap + phdr->p_offset - phdr->p_vaddr);
        }
        if(phdr->p_type == PT_INTERP) {
            interpreter = charmap + phdr->p_offset;
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

// size_t ElfMap::getSectionIndex(const char *name) {
//     auto offset = findSection(name);
//     if(offset == nullptr)
//         return static_cast<size_t>(-1);
//
//     char *charmap = static_cast<char *>(map);
//     Elf64_Ehdr *header = (Elf64_Ehdr *)map;
//     Elf64_Shdr *sheader = (Elf64_Shdr *)(charmap + header->e_shoff);
//     return (offset - static_cast<void *>(sheader)) / sizeof(Elf64_Shdr);
// }

size_t ElfMap::getEntryPoint() const {
    if (this->archType == ELFCLASS64) {
        return ElfMap::getEntryPoint<ElfType<ELFCLASS64> >();
    } else {
        return ElfMap::getEntryPoint<ElfType<ELFCLASS32> >();
    }
}

bool ElfMap::isExecutable() const {
    if (this->archType == ELFCLASS64) {
        return ElfMap::isExecutable<ElfType<ELFCLASS64> >();
    } else {
        return ElfMap::isExecutable<ElfType<ELFCLASS32> >();
    }
}

bool ElfMap::isSharedLibrary() const {
    if (this->archType == ELFCLASS64) {
        return ElfMap::isSharedLibrary<ElfType<ELFCLASS64> >();
    } else {
        return ElfMap::isSharedLibrary<ElfType<ELFCLASS32> >();
    }
}
