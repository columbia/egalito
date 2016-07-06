#include <iostream>
#include <iomanip>
#include <cstring>

#include <sys/mman.h>
#include <elf.h>

#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/disassemble.h"
#include "transform/sandbox.h"

#define ROUND_DOWN(x)   ((x) & ~0xfff)
#define ROUND_UP(x)     (((x) + 0xfff) & ~0xfff)

int main(int argc, char *argv[]) {
    if(argc < 1) return -1;

    try {
        ElfMap elf(argv[1]);
        SymbolList symbolList = SymbolList::buildSymbolList(&elf);

        auto segmentList = elf.getSegmentList();
        for(void *s : segmentList) {
            Elf64_Phdr *phdr = static_cast<Elf64_Phdr *>(s);
            if(phdr->p_type == PT_LOAD) {
                int prot = 0;
                if(phdr->p_flags & PF_R) prot |= PROT_READ;
                if(phdr->p_flags & PF_W) prot |= PROT_WRITE;
                if(phdr->p_flags & PF_X) prot |= PROT_EXEC;

                size_t memsz_pages  = ROUND_UP(phdr->p_memsz);
                size_t filesz_pages = ROUND_UP(phdr->p_filesz);
                //std::cout << "need " << memsz_pages << " mem pages for " << filesz_pages << " file pages\n";

                size_t vaddr = ROUND_DOWN(phdr->p_vaddr);

                void *mem = 0;
                if(memsz_pages > filesz_pages) {
                    mem = mmap((void *)vaddr,
                        memsz_pages,
                        prot,
                        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                        -1, 0);
                    munmap(mem, filesz_pages);
                    mem = mmap(mem, filesz_pages, prot,
                        MAP_PRIVATE | MAP_FIXED,
                        elf.getFileDescriptor(),
                        phdr->p_offset);
                    if(mem == (void *)-1) throw "Out of memory?";
                }
                else {  // no extra zero pages
                    mem = mmap((void *)vaddr,
                        memsz_pages,
                        prot,
                        MAP_PRIVATE | MAP_FIXED,
                        elf.getFileDescriptor(),
                        ROUND_DOWN(phdr->p_offset));
                    if(mem == (void *)-1) throw "Out of memory?";
                }

                std::cout << "mapped file offset " << std::hex << phdr->p_offset
                    << " (virtual address " << std::hex << phdr->p_vaddr << ")"
                    << " to " << std::hex << mem << std::endl;
            }
        }

        size_t entry_point = elf.getEntryPoint();
        std::cout << "jumping to ELF entry point at " << entry_point << std::endl;

        int (*mainp)(int, char **) = (int (*)(int, char **))entry_point;

        // invoke main
        {
            int argc = 1;
            char *argv[] = {"/dev/null", NULL};
            mainp(argc, argv);
        }
    }
    catch(const char *s) {
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    getchar();
    return 0;
}
