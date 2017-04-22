#ifndef EGALITO_ELF_ELF_XX_H
#define EGALITO_ELF_ELF_XX_H

#include <elf.h>

#ifdef ARCH_ARM
    // integral types
    typedef Elf32_Addr  ElfXX_Addr;
    typedef Elf32_Half  ElfXX_Half;
    typedef Elf32_Off   ElfXX_Off;
    typedef Elf32_Sword ElfXX_Sword;
    typedef Elf32_Word  ElfXX_Word;
    typedef Elf32_Xword ElfXX_Xword;
    typedef Elf32_Sxword ElfXX_Sxword;

    // structures
    typedef Elf32_Ehdr  ElfXX_Ehdr;
    typedef Elf32_Shdr  ElfXX_Shdr;
    typedef Elf32_Phdr  ElfXX_Phdr;
    typedef Elf32_Nhdr  ElfXX_Nhdr;
    typedef Elf32_Rela  ElfXX_Rela;
    typedef Elf32_Sym   ElfXX_Sym;
    typedef Elf32_Dyn   ElfXX_Dyn;

    // macros
    #define ELFCLASSXX  ELFCLASS32

    #define ELFXX_R_INFO    ELF32_R_INFO
    #define ELFXX_R_SYM     ELF32_R_SYM
    #define ELFXX_R_TYPE    ELF32_R_TYPE
    #define ELFXX_ST_TYPE   ELF32_ST_TYPE
    #define ELFXX_ST_BIND   ELF32_ST_BIND
    #define ELFXX_ST_INFO   ELF32_ST_INFO
#else  /* ARCH_X86_64, ARCH_AARCH64 */
    // integral types
    typedef Elf64_Addr  ElfXX_Addr;
    typedef Elf64_Half  ElfXX_Half;
    typedef Elf64_Off   ElfXX_Off;
    typedef Elf64_Sword ElfXX_Sword;
    typedef Elf64_Word  ElfXX_Word;
    typedef Elf64_Xword ElfXX_Xword;
    typedef Elf64_Sxword ElfXX_Sxword;

    // structures
    typedef Elf64_Ehdr  ElfXX_Ehdr;
    typedef Elf64_Shdr  ElfXX_Shdr;
    typedef Elf64_Phdr  ElfXX_Phdr;
    typedef Elf64_Nhdr  ElfXX_Nhdr;
    typedef Elf64_Rela  ElfXX_Rela;
    typedef Elf64_Sym   ElfXX_Sym;
    typedef Elf64_Dyn   ElfXX_Dyn;

    // macros
    #define ELFCLASSXX  ELFCLASS64

    #define ELFXX_R_INFO    ELF64_R_INFO
    #define ELFXX_R_SYM     ELF64_R_SYM
    #define ELFXX_R_TYPE    ELF64_R_TYPE
    #define ELFXX_ST_TYPE   ELF64_ST_TYPE
    #define ELFXX_ST_BIND   ELF64_ST_BIND
    #define ELFXX_ST_INFO   ELF64_ST_INFO
#endif

#endif
