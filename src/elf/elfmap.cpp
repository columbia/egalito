#include <iostream>
#include <sstream>
#include <cstring>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include "elfmap.h"
#include "log/log.h"

ElfMap::ElfMap() : map(nullptr), length(0), fd(-1) {
}

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

bool ElfMap::isElf(const char *filename) {
    try {
        ElfMap elf;
        elf.parseElf(filename);
    }
    catch(const char *error) {
        return false;
    }

    return true;
}

void ElfMap::setup() {
    verifyElf();
    makeSectionMap();
    makeSegmentList();
    makeVirtualAddresses();
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
    unsigned char *e_ident = ((ElfXX_Ehdr *)map)->e_ident;
    if(e_ident[EI_MAG0] != ELFMAG0
        || e_ident[EI_MAG1] != ELFMAG1
        || e_ident[EI_MAG2] != ELFMAG2
        || e_ident[EI_MAG3] != ELFMAG3) {

        throw "executable image does not have ELF magic\n";
    }

    // check architecture type
    unsigned char type = e_ident[EI_CLASS];
    if(type != ELFCLASSXX) {
        throw "file is unsupported\n";
    }
}

void ElfMap::makeSectionMap() {
    char *charmap = static_cast<char *>(map);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    if(sizeof(ElfXX_Shdr) != header->e_shentsize) {
        throw "header shentsize mismatch\n";
    }

    ElfXX_Shdr *sheader = (ElfXX_Shdr *)(charmap + header->e_shoff);
    //Elf64_Phdr *pheader = (Elf64_Phdr *)(charmap + header->e_phoff);

    this->shstrtab = charmap + sheader[header->e_shstrndx].sh_offset;

    for(int i = 0; i < header->e_shnum; i ++) {
        ElfXX_Shdr *s = &sheader[i];
        const char *name = shstrtab + s->sh_name;
        ElfSection *section = new ElfSection(i, name, s);
        //std::cout << "section [" << name << "]\n";

        sectionMap[name] = section;
        sectionList.push_back(section);
        LOG(11, "found section [" << name << "] in elf file");
    }
}

void ElfMap::makeSegmentList() {
    char *charmap = static_cast<char *>(map);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Phdr *pheader = (ElfXX_Phdr *)(charmap + header->e_phoff);

    for(int i = 0; i < header->e_phnum; i ++) {
        ElfXX_Phdr *phdr = &pheader[i];
        segmentList.push_back(static_cast<void *>(phdr));
    }
}

void ElfMap::makeVirtualAddresses() {
    baseAddress = 0;
    copyBase = 0;
    interpreter = nullptr;
    char *charmap = static_cast<char *>(map);

    for(std::map<std::string, ElfSection *>::iterator it = sectionMap.begin(); it != sectionMap.end(); ++it) {
        auto section = it->second;
        auto header = section->getHeader();
        section->setReadAddress(charmap + header->sh_offset);
        section->setVirtualAddress(header->sh_addr);
    }

    this->strtab = getSectionReadPtr<const char *>(".strtab");
    this->dynstr = getSectionReadPtr<const char *>(".dynstr");

    if (isObjectFile()) {
        copyBase = (address_t)(charmap);
        rwCopyBase = (address_t)(charmap);

        sectionMap[".data"]->setVirtualAddress(0x20000);
        sectionMap[".bss"]->setVirtualAddress(sectionMap[".data"]->getVirtualAddress() + sectionMap[".data"]->getHeader()->sh_size);
        sectionMap[".rodata"]->setVirtualAddress(sectionMap[".bss"]->getVirtualAddress() + sectionMap[".bss"]->getHeader()->sh_size);
        return;
    }

    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Phdr *pheader = (ElfXX_Phdr *)(charmap + header->e_phoff);

    for(int i = 0; i < header->e_phnum; i ++) {
        ElfXX_Phdr *phdr = &pheader[i];

        if(phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_X)) {
            copyBase = (address_t)(charmap + phdr->p_offset - phdr->p_vaddr);
        }
        if(phdr->p_type == PT_LOAD && phdr->p_flags == (PF_R | PF_W)) {
            rwCopyBase = (address_t)(charmap + phdr->p_offset - phdr->p_vaddr);
        }
        if(phdr->p_type == PT_INTERP) {
            interpreter = charmap + phdr->p_offset;
        }
    }
}

ElfSection *ElfMap::findSection(const char *name) const {
    auto it = sectionMap.find(name);
    if(it == sectionMap.end()) return nullptr;

    return it->second;
}

ElfSection *ElfMap::findSection(int index) const {
    if(static_cast<std::vector<ElfSection *>::size_type>(index)
        < sectionList.size()) {

        return sectionList[index];
    }
    return nullptr;
}

std::vector<void *> ElfMap::findSectionsByType(int type) const {
    std::vector<void *> sections;
    ElfXX_Shdr sCast;

    char *charmap = static_cast<char *>(map);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Shdr *sheader = (ElfXX_Shdr *)(charmap + header->e_shoff);
    for(int i = 0; i < header->e_shnum; i ++) {
        ElfXX_Shdr *s = &sheader[i];

        if(s->sh_type == static_cast<decltype(sCast.sh_type)>(type)) {
            sections.push_back(static_cast<void *>(s));
        }
    }

    return std::move(sections);
}

std::vector<void *> ElfMap::findSectionsByFlag(long flag) const {
    std::vector<void *> sections;

    char *charmap = static_cast<char *>(map);
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    ElfXX_Shdr *sheader = (ElfXX_Shdr *)(charmap + header->e_shoff);
    for(int i = 0; i < header->e_shnum; i ++) {
        ElfXX_Shdr *s = &sheader[i];

        if(s->sh_flags & flag) {
            sections.push_back(static_cast<void *>(s));
        }
    }

    return sections;
}

size_t ElfMap::getEntryPoint() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_entry;
}

bool ElfMap::isExecutable() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_type == ET_EXEC;
}

bool ElfMap::isSharedLibrary() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_type == ET_DYN;
}

bool ElfMap::isObjectFile() const {
    ElfXX_Ehdr *header = (ElfXX_Ehdr *)map;
    return header->e_type == ET_REL;
}

bool ElfMap::isDynamic() const {
    return findSection(".dynamic") != nullptr;
}

bool ElfMap::hasRelocations() const {
    return !findSectionsByType(SHT_RELA).empty();
    //return findSection(".rela.text") != nullptr;
}
