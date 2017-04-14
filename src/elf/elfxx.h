#ifndef EGALITO_ELF_TYPES_H
#define EGALITO_ELF_TYPES_H

#include <elf.h>

#ifdef ARCH_ARM
		#define ElfXX_Ehdr  Elf32_Ehdr
		#define ElfXX_Shdr  Elf32_Shdr
		#define ElfXX_Phdr  Elf32_Phdr
		#define ElfXX_Nhdr  Elf32_Nhdr
		#define ElfXX_Rela  Elf32_Rela
		#define ElfXX_Sym   Elf32_Sym
		#define ElfXX_Dyn   Elf32_Dyn

		#define ELFCLASSXX ELFCLASS32

		#define ELFXX_R_INFO  ELF32_R_INFO
		#define ELFXX_R_SYM   ELF32_R_SYM
		#define ELFXX_R_TYPE  ELF32_R_TYPE
		#define ELFXX_ST_TYPE ELF32_ST_TYPE
		#define ELFXX_ST_BIND ELF32_ST_BIND
		#define ELFXX_ST_INFO ELF32_ST_INFO

		#define ElfXX_Addr  Elf32_Addr
		#define ElfXX_Half  Elf32_Half
		#define ElfXX_Off   Elf32_Off
		#define ElfXX_Sword Elf32_Sword
		#define ElfXX_Word  Elf32_Word
#else
		#define ElfXX_Ehdr  Elf64_Ehdr
		#define ElfXX_Shdr  Elf64_Shdr
		#define ElfXX_Phdr  Elf64_Phdr
		#define ElfXX_Nhdr  Elf64_Nhdr
		#define ElfXX_Rela  Elf64_Rela
		#define ElfXX_Sym   Elf64_Sym
		#define ElfXX_Dyn   Elf64_Dyn

		#define ELFCLASSXX ELFCLASS64

		#define ELFXX_R_INFO  ELF64_R_INFO
		#define ELFXX_R_SYM   ELF64_R_SYM
		#define ELFXX_R_TYPE  ELF64_R_TYPE
		#define ELFXX_ST_TYPE ELF64_ST_TYPE
		#define ELFXX_ST_BIND ELF64_ST_BIND
		#define ELFXX_ST_INFO ELF64_ST_INFO

		#define ElfXX_Addr  Elf64_Addr
		#define ElfXX_Half  Elf64_Half
		#define ElfXX_SHalf Elf64_SHalf
		#define ElfXX_Off   Elf64_Off
		#define ElfXX_Sword Elf64_Sword
		#define ElfXX_Word  Elf64_Word
		#define ElfXX_Xword Elf64_Xword
		#define ElfXX_Sxword Elf64_Sxword
#endif

#endif
