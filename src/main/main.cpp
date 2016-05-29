#include <iostream>
#include <iomanip>
#include <cstdio>
#include "main.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"

#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

void disassemble(const uint8_t *code, size_t length, address_t realAddress);

int main(int argc, char *argv[]) {
    if(argc > 1) {
        try {
            ElfMap elf(argv[1]);
            SymbolList symbolList = SymbolList::buildSymbolList(&elf);

            auto baseAddr = elf.getCopyBaseAddress();
            for(auto s : symbolList) {
                auto sym = s.second;
                std::cout << "---[" << sym->getName() << "]---\n";
                auto addr = sym->getAddress();
                std::cout << "addr " << std::hex << addr
                    << " -> " << std::hex << addr + baseAddr << "\n";
                disassemble((uint8_t *)(addr + baseAddr), sym->getSize(), addr);
            }
        }
        catch(const char *s) {
            std::cerr << "Error: " << s;
        }
    }
}

void disassemble(const uint8_t *code, size_t length, address_t realAddress) {
    csh handle;
    cs_insn *insn;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return;
    }

    // switch to AT&T syntax
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

    size_t count = cs_disasm(handle, code, length, realAddress, 0, &insn);
    if(count > 0) {
        for(size_t j = 0; j < count; j++) {
            std::printf("0x%08lx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                    insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else std::printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);
}
