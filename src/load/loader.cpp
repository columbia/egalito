#include <iostream>
#include <iomanip>
#include <cstring>

#include "segmap.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "elf/reloc.h"
#include "elf/auxv.h"
#include "chunk/chunk.h"
#include "chunk/chunklist.h"
#include "chunk/disassemble.h"
#include "transform/sandbox.h"

#include <elf.h>

extern address_t entry;
extern "C" void _start2(void);

void examineElf(ElfMap *elf);

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

        examineElf(elf);
        //examineElf(interpreter);

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

void examineElf(ElfMap *elf) {
    SymbolList symbolList = SymbolList::buildSymbolList(elf);

    std::cout << "\n=== Initial code disassembly ===\n";

    auto baseAddr = elf->getCopyBaseAddress();
    for(auto sym : symbolList) {
        std::cout << "---[" << sym->getName() << "]---\n";
        auto addr = sym->getAddress();
        std::cout << "addr " << std::hex << addr
            << " -> " << std::hex << addr + baseAddr << "\n";
        Disassemble::debug((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
            &symbolList);
    }

    std::cout << "\n=== Creating internal data structures ===\n";

    ChunkList<Function> functionList;
    for(auto sym : symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, &symbolList);

        std::cout << "---[" << sym->getName() << "]---\n";
        for(auto bb : *function) {
            std::cout << bb->getName() << ":\n";
            for(auto instr : *bb) {
                std::cout << "    ";
                instr->dump();
            }
        }

        functionList.add(function);
    }

    for(auto f : functionList) {
        for(auto bb : *f) {
            for(auto instr : *bb) {
                if(instr->hasLink()) {
                    auto link = instr->getLink();

                    Function *target = functionList.find(link->getTargetAddress());
                    if(!target) continue;

                    std::cout << "FOUND REFERENCE from "
                        << f->getName() << " -> " << target->getName()
                        << std::endl;

                    instr->makeLink(
                        link->getSource()->getOffset(),
                        new RelativePosition(target, 0));
                }
            }
        }
    }

    RelocList relocList = RelocList::buildRelocList(elf);
}
