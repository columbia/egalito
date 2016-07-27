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

#include <elf.h>

address_t entry = 0;
extern "C" void _start2(void);

int main(int argc, char *argv[]) {
    if(argc < 1) return -1;

    std::cout << "trying to load [" << argv[1] << "]...\n";

    try {
        ElfMap elf(argv[1]);
        ElfMap interpreter("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");

        address_t baseAddress = elf.isSharedLibrary() ? 0x4000000 : 0;
        address_t interpreterAddress = 0x7000000;

        SegMap::mapSegments(elf, baseAddress);
        SegMap::mapSegments(interpreter, interpreterAddress);

        address_t elfEntry = elf.getEntryPoint() + baseAddress;
        entry = interpreter.getEntryPoint() + interpreterAddress;
        std::cout << "jumping to interpreter entry point at " << entry << std::endl;
        std::cout << "while ELF entry point is " << elfEntry << std::endl;

        interpreter.adjustAuxV(argv, interpreterAddress, true);
        elf.adjustAuxV(argv, baseAddress, false);
        _start2();  // never returns
    }
    catch(const char *s) {
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    return 0;
}
