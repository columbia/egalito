#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "debugelf.h"
#include "chunk/concrete.h"  // for Function

#include "log/log.h"

DebugElf::DebugElf() {
    symbols = (Elf64_Sym *)mmap(NULL, 0x1000,
        PROT_READ|PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    symbols_size = 0x1000;
    symbols_used = 0;

    strtable = (char *)mmap(NULL, 0x1000,
        PROT_READ|PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    strtable_size = 0x1000;
    const char *strtable_seed = "\0.symtab\0.strtab\0.text";

    for(int i = 0; i < 23; i ++) {
        strtable[i] = strtable_seed[i];
    }
    strtable_used = 23;

    start = -1;
    end = 0;
}

DebugElf::~DebugElf() {
    munmap(symbols, symbols_size);
    munmap(strtable, strtable_size);
}

void DebugElf::add(unsigned long addr, unsigned long size, const char *name) {
    if(symbols_size < (symbols_used+1)*sizeof(Elf64_Sym)) {
        symbols = (Elf64_Sym *)mremap(symbols,
            symbols_size, symbols_size + 0x1000,
            MREMAP_MAYMOVE);

        symbols_size += 0x1000;
    }

    symbols[symbols_used].st_value = addr;
    symbols[symbols_used].st_size = size;
    symbols[symbols_used].st_name = strtable_used;
    symbols[symbols_used].st_other = 0;
    symbols[symbols_used].st_shndx = 3;
    symbols[symbols_used].st_info = (STB_GLOBAL<<4) | STT_FUNC;

    symbols_used ++;

    if(addr < start) start = addr;
    if(addr+size > end) end = addr+size;

    size_t name_len = 0;
    const char *p = name;
    while(*p++) name_len ++;

    if((name_len+1) + strtable_used > strtable_size) {
        strtable = (char *)mremap(strtable,
            strtable_size, strtable_size + 0x1000,
            MREMAP_MAYMOVE);

        strtable_size += 0x1000;
    }

    char *q = strtable + strtable_used;

    p = name;
    while(*p) {
        *q = *p;
        q ++, p ++;
    }

    // +1 for the NULL terminator
    strtable_used += name_len + 1;
}

void DebugElf::add(Function *func, const char *suffix) {
    // assumes each symbol names plus the suffix is <= 1024 chars long
    char name[1024];
    auto cppName = func->getName();
    const char *p = cppName.c_str();
    char *q = name;
    while(*p) {
        *q = *p;
        p ++, q ++;
    }
    p = suffix;
    while(*p) {
        *q = *p;
        p ++, q ++;
    }
    *q = 0;
    LOG(11, "debug symbol [" << name << "] at " << func->getAddress()
        << " size " << func->getSize());
    add(func->getAddress(), func->getSize(), name);
}

void DebugElf::writeTo(int fd) {
    // build ELF header
    Elf64_Ehdr ehdr;
    // sensible defaults
    const unsigned char ident[] = {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    for(size_t i = 0; i < EI_NIDENT; i ++) ehdr.e_ident[i] = ident[i];

    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = EM_386;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = 0;
    ehdr.e_phoff = 0; // one program header, NULL
    ehdr.e_shoff = sizeof(Elf64_Ehdr); // section head go right after elf head
    ehdr.e_flags = 0;
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 0; // one NULL program header
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    // NULL section + symbols + string table + text section
    ehdr.e_shnum = 4;
    ehdr.e_shstrndx = 2;

    write(fd, &ehdr, sizeof(ehdr));

    // build section headers
    Elf64_Shdr shdr;
    for(size_t i = 0; i < sizeof(Elf64_Shdr); i ++) {
        ((char *)&shdr)[i] = 0;
    }
    write(fd, &shdr, sizeof(shdr));

    shdr.sh_name = 1; // .symtab
    shdr.sh_type = SHT_SYMTAB;
    shdr.sh_flags = 0;
    shdr.sh_addr = 0;
    shdr.sh_offset = sizeof(Elf64_Ehdr) + 4*sizeof(Elf64_Shdr);
    shdr.sh_size = symbols_used * sizeof(Elf64_Sym);
    shdr.sh_link = 2;
    shdr.sh_info = 0; // all symbols global
    shdr.sh_addralign = 1;
    shdr.sh_entsize = sizeof(Elf64_Sym);
    write(fd, &shdr, sizeof(shdr));

    shdr.sh_name = 9; // .strtab
    shdr.sh_type = SHT_STRTAB;
    shdr.sh_offset += shdr.sh_size;
    shdr.sh_size = strtable_used;
    shdr.sh_link = 0;
    shdr.sh_entsize = 0;
    write(fd, &shdr, sizeof(shdr));

    shdr.sh_name = 17; // .text
    shdr.sh_type = SHT_NOBITS;
    shdr.sh_offset = 0;

    end += start;
    start = 0;  // symbol values are added to this, make math easy
    end = (end + 0xfffff) & ~0xfffff;  // round end up
    shdr.sh_addr = start;  // 0
    shdr.sh_size = end - start;  // end

    shdr.sh_link = 0;
    shdr.sh_entsize = 0;
    shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    shdr.sh_addralign = 1;
    write(fd, &shdr, sizeof(shdr));

    write(fd, symbols,
        symbols_used*sizeof(Elf64_Sym));
    write(fd, strtable, strtable_used);
}

void DebugElf::writeTo(const char *filename) {
    int fd = open(filename, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if(fd == -1) return;

    writeTo(fd);

    close(fd);
}
