#include <iostream>
#include <iomanip>
#include <cstring>

#include "segmap.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "elf/reloc.h"
#include "elf/auxv.h"
#include "chunk/chunk.h"
#include "chunk/disassemble.h"
#include "transform/sandbox.h"

#include <elf.h>

extern address_t entry;
extern "C" void _start2(void);

int main(int argc, char *argv[]) {
    if(argc < 1) return -1;

    std::cout << "trying to load [" << argv[1] << "]...\n";

    try {
        ElfMap *elf = new ElfMap(argv[1]);
        ElfMap *interpreter = nullptr;
        if(elf->hasInterpreter()) {
            interpreter = new ElfMap(elf->getInterpreter());
        }

        // set base addresses and map PT_LOAD sections into memory
        const address_t baseAddress = elf->isSharedLibrary() ? 0x4000000 : 0;
        const address_t interpreterAddress = 0x7000000;
        elf->setBaseAddress(baseAddress);
        SegMap::mapSegments(*elf, elf->getBaseAddress());
        if(interpreter) {
            interpreter->setBaseAddress(interpreterAddress);
            SegMap::mapSegments(*interpreter, interpreter->getBaseAddress());
        }

        // find entry point
        if(interpreter) {
            entry = interpreter->getEntryPoint() + interpreterAddress;
        }
        else {
            entry = elf->getEntryPoint() + baseAddress;
        }
        std::cout << "jumping to entry point at " << entry << std::endl;

        // set up execution environment
        adjustAuxiliaryVector(argv, elf, interpreter);

        // jump to the interpreter/target program (never returns)
        _start2();
    }
    catch(const char *s) {
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    return 0;
}
