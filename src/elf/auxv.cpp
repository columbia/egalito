#include <iostream>
#include <elf.h>
#include "auxv.h"
#include "log/log.h"

static address_t *findAuxiliaryVector(char **argv) {
    address_t *address = reinterpret_cast<address_t *>(argv);
    
    //address ++;  // skip argc
    while(*address++) {}  // skip argv entries
    while(*address++) {}  // skip envp entries
    
    return address;
}

void adjustAuxiliaryVector(char **argv, ElfMap *elf, ElfMap *interpreter) {
    ElfMap *beginning = (interpreter ? interpreter : elf);
    Elf64_Ehdr *header = (Elf64_Ehdr *)elf->getCharmap();

    address_t *auxv = findAuxiliaryVector(argv);

    CLOG(0, "fixing auxiliary vector");

    // Loop through all auxiliary vector entries, stopping at the terminating
    // entry of type AT_NULL.
    for(address_t *p = auxv; p[0] != AT_NULL; p += 2) {
        address_t type = p[0];
        address_t *new_value = &p[1];
        switch(type) {
        case AT_BASE:
            *new_value = reinterpret_cast<address_t>(beginning->getCharmap());
            CLOG(1, "    auxv base address: 0x%lx", *new_value);
            break;
        case AT_ENTRY:
            *new_value = beginning->getBaseAddress()
                + beginning->getEntryPoint();
            CLOG(1, "    auxv entry point: 0x%lx", *new_value);
            break;
        case AT_PHDR:
            *new_value = reinterpret_cast<address_t>(elf->getCharmap())
                + header->e_phoff;
            break;
        case AT_PHENT:
            *new_value = header->e_phentsize;
            break;
        case AT_PHNUM:
            *new_value = header->e_phnum;
            break;
#if 0
        case AT_EXECFN:
            static const char *fakeFilename
                = "./hello";
            std::printf("AUXV: old exec filename is [%s]\n",
                reinterpret_cast<char *>(*new_value));
            *new_value = reinterpret_cast<address_t>(fakeFilename);
            std::printf("AUXV: new exec filename is [%s]\n",
                reinterpret_cast<char *>(*new_value));
            break;
#endif
        default:
            break;
        }
    }
}
