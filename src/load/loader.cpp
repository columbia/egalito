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
#include "break/signals.h"
#include "break/breakpoint.h"
#include "log/log.h"

#include <elf.h>

LOGGING_PRELUDE("LOAD");

extern address_t entry;
extern "C" void _start2(void);

void examineElf(ElfMap *elf);
void setBreakpointsInInterpreter(ElfMap *elf);
void writeOutElf(ElfMap *elf, ChunkList<Function> &functionList);

int main(int argc, char *argv[]) {
    if(argc < 2) return -1;

    std::cout << "trying to load [" << argv[1] << "]...\n";
    LOG(0, "loading ELF program [" << argv[1] << "]");
    LOG(10, "loading ELF program [" << argv[1] << "]");
    CLOG(0, "hi there %d", 42);

    Signals::registerHandlers();

    try {
        ElfMap *elf = new ElfMap(argv[1]);
        ElfMap *interpreter = nullptr;
        if(elf->hasInterpreter()) {
            interpreter = new ElfMap(elf->getInterpreter());
        }

        // set base addresses and map PT_LOAD sections into memory
        const address_t baseAddress = elf->isSharedLibrary() ? 0x4000000 : 0;
        const address_t interpreterAddress = interpreter->isSharedLibrary() ? 0x7000000 : 0;
        elf->setBaseAddress(baseAddress);
        SegMap::mapSegments(*elf, elf->getBaseAddress());
        if(interpreter) {
            interpreter->setBaseAddress(interpreterAddress);
            SegMap::mapSegments(*interpreter, interpreter->getBaseAddress());
        }

        examineElf(elf);
        //examineElf(interpreter);
        setBreakpointsInInterpreter(interpreter);

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

    RelocList relocList = RelocList::buildRelocList(elf, &symbolList);
    for(auto r : relocList) {
        if(!r->getSymbol()) continue;
        Function *target = functionList.find(r->getSymbol()->getName());
        if(target) {
            std::cout << "FOUND RELOCATION from "
                << r->getAddress() << " -> " << target->getName()
                << std::endl;
        }
    }

    writeOutElf(elf, functionList);
}

void setBreakpointsInInterpreter(ElfMap *elf) {
    SymbolList symbolList = SymbolList::buildSymbolList(elf);

    auto baseAddr = elf->getCopyBaseAddress();
    ChunkList<Function> functionList;
    for(auto sym : symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, &symbolList);
        functionList.add(function);
    }

    Function *f = functionList.find("call_init.part.0");
    if(f) {
        BreakpointManager *bm = new BreakpointManager();
        bm->set(f->getAddress() + elf->getBaseAddress());
    }
    else std::cout << "Unable to find ld.so function to set breakpoints!\n";
}

void writeOutElf(ElfMap *elf, ChunkList<Function> &functionList) {
    auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
    Sandbox *sandbox = new SandboxImpl<
        MemoryBacking, WatermarkAllocator<MemoryBacking>>(backing);

    std::cout << "\n=== Copying code into sandbox ===\n";
    for(auto f : functionList) {
        auto slot = sandbox->allocate(f->getSize());
        std::cout << "ALLOC " << slot.getAddress() << " for " << f->getName() << "\n";
        f->setAddress(slot.getAddress());
        //f->assignTo(new Slot(slot));
    }
    for(auto f : functionList) {
        std::cout << "writing out " << f->getName() << "\n";
        f->writeTo(sandbox);
    }
    sandbox->finalize();

    for(auto f : functionList) {
        std::cout << "---[" << f->getName() << "]---\n";
#if 1
        for(auto bb : *f) {
            for(auto instr : *bb) {
                std::cout << "    ";
                instr->dump();
            }
        }
#endif
    }
}
