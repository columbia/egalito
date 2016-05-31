#include <iostream>
#include <iomanip>
#include <cstdio>
#include "main.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/disassemble.h"

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
                Disassemble::debug((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
                    &symbolList);
            }
            for(auto s : symbolList) {
                auto sym = s.second;
                std::cout << "---[" << sym->getName() << "]---\n";
                Disassemble::function(sym, baseAddr, &symbolList);
            }
        }
        catch(const char *s) {
            std::cerr << "Error: " << s;
        }
    }
}
