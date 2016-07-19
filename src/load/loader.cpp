#include <iostream>
#include <iomanip>
#include <cstring>

#include "segmap.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "elf/reloc.h"
#include "chunk/chunk.h"
#include "chunk/disassemble.h"
#include "transform/sandbox.h"

static void (*entry)(void) = 0;

int main(int argc, char *argv[]) {
    if(argc < 1) return -1;

    try {
        ElfMap elf(argv[1]);
        //SymbolList symbolList = SymbolList::buildSymbolList(&elf);
        //RelocList relocList = RelocList::buildRelocList(&elf);

        const address_t baseAddress = 0x7000000;
        //const address_t baseAddress = 0x777000000;
        //const address_t baseAddress = 0;
        SegMap::mapSegments(elf, baseAddress);

        size_t entry_point = elf.getEntryPoint() + baseAddress;
        std::cout << "jumping to ELF entry point at " << entry_point << std::endl;

        int (*mainp)(int, char **) = (int (*)(int, char **))entry_point;
        entry = (void (*)(void))entry_point;

        // invoke main
        if(1) {
            int argc = 2;
            //char *argv[] = {"/dev/null", NULL};
            char *argv[] = {"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "test/hi0-z", NULL};
            __asm__ __volatile__ (
                "push %%rax\n"
                "push %%rbx\n"
                "jmp  *%%rcx\n"
                "hlt\n"
                : : "a"(argc), "b"(argv), "c"(mainp)
            );
            //mainp(argc, argv);
        }
    }
    catch(const char *s) {
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    getchar();

    (*entry)();
    return 0;
}
