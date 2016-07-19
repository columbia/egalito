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

        //const address_t baseAddress = 0x7000000;
        const address_t baseAddress = 0x777000000;
        //const address_t baseAddress = 0;
        SegMap::mapSegments(elf, baseAddress);

        size_t entry_point = elf.getEntryPoint();
        std::cout << "jumping to ELF entry point at " << entry_point << std::endl;

        entry_point += baseAddress;

        int (*mainp)(int, char **) = (int (*)(int, char **))entry_point;
        entry = (void (*)(void))entry_point;

        // invoke main
        if(0) {
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

    (*entry)();
    return 0;
}
