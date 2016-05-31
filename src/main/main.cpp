#include <iostream>
#include <iomanip>
#include <cstdio>
#include "main.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
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
                Function *function = Disassemble::function(sym, baseAddr, &symbolList);

                std::cout << "---[" << sym->getName() << "]---\n";
                for(auto bb : *function) {
                    std::cout << bb->getName() << ":\n";
                    for(auto instr : *bb) {
                        std::cout << "    ";
                        Disassemble::printInstruction(&instr.raw());
                    }
                }

                delete function;
            }
        }
        catch(const char *s) {
            std::cerr << "Error: " << s;
        }
    }
}
