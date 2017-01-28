#include <iostream>
#include <iomanip>
#include <cstring>

#include "usage.h"
#include "segmap.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "elf/reloc.h"
#include "elf/auxv.h"
#include "chunk/chunk.h"
#include "chunk/chunklist.h"
#include "chunk/disassemble.h"
#include "chunk/resolve.h"
#include "chunk/dump.h"
#include "transform/sandbox.h"
#include "break/signals.h"
#include "break/breakpoint.h"
#include "log/registry.h"
#include "log/log.h"

#include <elf.h>

extern address_t entry;
extern "C" void _start2(void);

void examineElf(ElfMap *elf);
void setBreakpointsInInterpreter(ElfMap *elf);
void writeOutElf(ElfMap *elf, std::vector<Function> &functionList);

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printUsage(argv[0]);
        return -1;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        printUsage(argv[0]);
        return -2;
    }
    GroupRegistry::getInstance()->dumpSettings();

    LOG(0, "loading ELF program [" << argv[1] << "]");

    Signals::registerHandlers();

#if 1
    try {
        ElfMap *elf = new ElfMap(argv[1]);
        ElfMap *interpreter = nullptr;
        if(elf->hasInterpreter()) {
            interpreter = new ElfMap(elf->getInterpreter());
        }

        // set base addresses and map PT_LOAD sections into memory
        const address_t baseAddress = elf->isSharedLibrary() ? 0x4000000 : 0;
        const address_t interpreterAddress = interpreter && interpreter->isSharedLibrary()
            ? 0x7000000 : 0;
        elf->setBaseAddress(baseAddress);
        SegMap::mapSegments(*elf, elf->getBaseAddress());
        if(interpreter) {
            interpreter->setBaseAddress(interpreterAddress);
            SegMap::mapSegments(*interpreter, interpreter->getBaseAddress());
        }

        examineElf(elf);
        if(interpreter) {
            //examineElf(interpreter);
            //setBreakpointsInInterpreter(interpreter);
        }

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
#endif

    return 0;
}

#if 1
void examineElf(ElfMap *elf) {
    SymbolList *symbolList = SymbolList::buildSymbolList(elf);

    LOG(1, "");
    LOG(1, "=== Initial code disassembly ===");

    auto baseAddr = elf->getCopyBaseAddress();
    for(auto sym : *symbolList) {
        LOG(2, "---[" << sym->getName() << "]---");
        auto addr = sym->getAddress();
        LOG(2, "addr " << std::hex << addr
            << " -> " << std::hex << addr + baseAddr);
        Disassemble::debug((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
            symbolList);
    }

    LOG(1, "");
    LOG(1, "=== Creating internal data structures ===");

    Module *module = new Module();
    std::vector<Function *> functionList;
    for(auto sym : *symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, symbolList);
        module->getChildren()->add(function);
        functionList.push_back(function);
    }

    ChunkResolver resolver(functionList);
    module->accept(&resolver);

    ChunkDumper dumper;
    module->accept(&dumper);

    RelocList *relocList = RelocList::buildRelocList(elf, symbolList);
    module->getChildren()->setNamed(new NamedChunkList<Function>());
    module->getChildren()->setSpatial(new SpatialChunkList<Function>());
    for(auto r : *relocList) {
        if(!r->getSymbol()) continue;
        Function *target = module->getChildren()->getNamed()->find(r->getSymbol()->getName());
        if(target) {
            LOG(2, "FOUND RELOCATION from "
                << r->getAddress() << " -> " << target->getName());

            auto f = module->getChildren()->getSpatial()->findContaining(r->getAddress());
            if(f) {
                LOG(2, "    inside function " << f->getName());

                f->getChildren()->setSpatial(new SpatialChunkList<Block>());
                auto b = f->getChildren()->getSpatial()->findContaining(r->getAddress());
                if(b) {
                    LOG(2, "    inside block " << b->getName());
                    b->getChildren()->setSpatial(new SpatialChunkList<Instruction>());
                    auto i = b->getChildren()->getSpatial()->findContaining(r->getAddress());
                    if(i) {
                        LOG(2, "    found instruction!!");
                        if(auto v = dynamic_cast<ControlFlowInstruction *>(i->getSemantic())) {
                            LOG(2, "    (duplicate of control flow)");
                        }
                        else if(auto v = dynamic_cast<DisassembledInstruction *>(i->getSemantic())) {
                            auto ri = new RelocationInstruction(DisassembledStorage(*v->getCapstone()));
                            ri->setLink(new NormalLink(target));
                            i->setSemantic(ri);
                        }
                    }
                }
            }
        }
    }

    module->accept(&dumper);

    //writeOutElf(elf, functionList);
}

#if 0
void setBreakpointsInInterpreter(ElfMap *elf) {
    SymbolList *symbolList = SymbolList::buildSymbolList(elf);

    auto baseAddr = elf->getCopyBaseAddress();
    ChunkList<Function> functionList;
    for(auto sym : *symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, symbolList);
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
#endif

#if 0
void writeOutElf(ElfMap *elf, std::vector<Function> &functionList) {
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

        sandbox->allocate(0x10000);  // skip some pages
    }
    for(auto f : functionList) {
        LOG(2, "writing out " << f->getName() << " at " << std::hex << f->getAddress());
        f->writeTo(sandbox);
    }
    sandbox->finalize();

    for(auto f : functionList) {
        LOG(2, "---[" << f->getName() << "]--- at " << std::hex << f->getAddress());
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
#endif
#endif
