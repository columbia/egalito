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

            std::cout << "\n=== Initial code disassembly ===\n";

            auto baseAddr = elf.getCopyBaseAddress();
            for(auto sym : symbolList) {
                std::cout << "---[" << sym->getName() << "]---\n";
                auto addr = sym->getAddress();
                std::cout << "addr " << std::hex << addr
                    << " -> " << std::hex << addr + baseAddr << "\n";
                Disassemble::debug((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
                    &symbolList);
            }

            std::cout << "\n=== Creating internal data structures ===\n";

            std::vector<Function *> functionList;
            for(auto sym : symbolList) {
                Function *function = Disassemble::function(sym, baseAddr, &symbolList);

                (*function->begin())->append(Disassemble::makeInstruction("\xcc"));
                (*function->begin())->append(Disassemble::makeInstruction("\xcc"));
                (*function->begin())->append(Disassemble::makeInstruction("\xcc"));

                std::cout << "---[" << sym->getName() << "]---\n";
                for(auto bb : *function) {
                    std::cout << bb->getName() << ":\n";
                    for(auto &instr : *bb) {
                        std::cout << "    ";
                        instr.dump();
                    }
                }

                functionList.push_back(function);
            }

            std::cout << "\n=== Re-compacting code at new location ===\n";

            address_t watermark = 0x10000;
            for(auto f : functionList) {
                f->setAddress(watermark);
                watermark += f->getSize();
            }

            for(auto f : functionList) {
                std::cout << "---[" << f->getName() << "]---\n";
                for(auto bb : *f) {
                    for(auto &instr : *bb) {
                        std::cout << "    ";
                        instr.dump();
                    }
                }
            }
        }
        catch(const char *s) {
            std::cerr << "Error: " << s;
        }
    }
}
