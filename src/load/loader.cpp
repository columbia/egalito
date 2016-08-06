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
#include "log/registry.h"
#include "log/log.h"

#include <elf.h>

LOGGING_PRELUDE("LOAD");

extern address_t entry;
extern "C" void _start2(void);

void examineElf(ElfMap *elf);
void setBreakpointsInInterpreter(ElfMap *elf);
void writeOutElf(ElfMap *elf, ChunkList<Function> &functionList);

int main(int argc, char *argv[]) {
    try {
        throw "??";
    }
    catch(const char *s) {
        std::cout << "exception " << s << std::endl;
    }
    if(argc < 2) return -1;

    LOG(0, "loading ELF program [" << argv[1] << "]");

    Signals::registerHandlers();
    SettingsParser().parseEnvVar("EGALITO_DEBUG");
    FileRegistry::getInstance()->dumpSettings();

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
        CLOG(0, "jumping to entry point at 0x%lx", entry);

        // set up execution environment
        adjustAuxiliaryVector(argv, elf, interpreter);

        // jump to the interpreter/target program (never returns)
        _start2();
    }
    catch(const char *s) {
        LOG(0, "ERROR: " << s);
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    return 0;
}

void examineElf(ElfMap *elf) {
    SymbolList symbolList = SymbolList::buildSymbolList(elf);

    LOG(1, "");
    LOG(1, "=== Initial code disassembly ===");

    auto baseAddr = elf->getCopyBaseAddress();
    for(auto sym : symbolList) {
        LOG(2, "---[" << sym->getName() << "]---");
        auto addr = sym->getAddress();
        LOG(2, "addr " << std::hex << addr
            << " -> " << std::hex << addr + baseAddr);
        Disassemble::debug((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
            &symbolList);
    }

    LOG(1, "");
    LOG(1, "=== Creating internal data structures ===");

    ChunkList<Function> functionList;
    for(auto sym : symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, &symbolList);

        LOG(2, "---[" << sym->getName() << "]---");
        for(auto bb : *function) {
            LOG(3, bb->getName() << ":");
            for(auto instr : *bb) {
                LOG0(3, "    ");
                IF_LOG(3) instr->dump();
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

                    LOG(2, "FOUND REFERENCE from "
                        << f->getName() << " -> " << target->getName());

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
            LOG(2, "FOUND RELOCATION from "
                << r->getAddress() << " -> " << target->getName());
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

#if 0
    Function *f = functionList.find("call_init.part.0");
    if(f) {
        BreakpointManager *bm = new BreakpointManager();
        bm->set(f->getAddress() + elf->getBaseAddress());
    }
    else std::cout << "Unable to find ld.so function to set breakpoints!\n";
#endif
}

void writeOutElf(ElfMap *elf, ChunkList<Function> &functionList) {
    auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
    Sandbox *sandbox = new SandboxImpl<
        MemoryBacking, WatermarkAllocator<MemoryBacking>>(backing);

    LOG(1, "");
    LOG(1, "=== Copying code into sandbox ===");
    for(auto f : functionList) {
        auto slot = sandbox->allocate(f->getSize());
        LOG(2, "ALLOC " << slot.getAddress() << " for " << f->getName());
        f->setAddress(slot.getAddress());
        //f->assignTo(new Slot(slot));
    }
    for(auto f : functionList) {
        LOG(2, "writing out " << f->getName());
        f->writeTo(sandbox);
    }
    sandbox->finalize();

    for(auto f : functionList) {
        LOG(2, "---[" << f->getName() << "]---");
#if 1
        for(auto bb : *f) {
            for(auto instr : *bb) {
                LOG0(3, "    ");
                IF_LOG(3) instr->dump();
            }
        }
#endif
    }
}
