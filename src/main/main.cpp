#include <iostream>
#include <iomanip>
#include <cstdio>
#include <cstring>
#include "main.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/disassemble.h"
#include "chunk/dump.h"
#include "chunk/resolve.h"
#include "transform/sandbox.h"

int main(int argc, char *argv[]) {
    if(argc < 2) return -1;

    try {
        ElfMap elf(argv[1]);
        SymbolList *symbolList = SymbolList::buildSymbolList(&elf);

        std::cout << "\n=== Initial code disassembly ===\n";

        auto baseAddr = elf.getCopyBaseAddress();
        for(auto sym : *symbolList) {
            std::cout << "---[" << sym->getName() << "]---\n";
            auto addr = sym->getAddress();
            std::cout << "addr " << std::hex << addr
                << " -> " << std::hex << addr + baseAddr << "\n";
            Disassemble::debug((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
                symbolList);
        }

        std::cout << "\n=== Creating internal data structures ===\n";

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

        {
            auto bb = functionList[3]->getChildren()->get(1);
            Instruction *cc = new Instruction(new DisassembledInstruction(Disassemble::getInsn("\xcc")));
            //cc->setPosition(new RelativePosition(cc, 0));
            cc->setPosition(new SubsequentPosition(bb->getChildren()->get(0)));
            bb->getChildren()->insertAt(1, cc);
            bb->getChildren()->get(2)->setPosition(new SubsequentPosition(bb->getChildren()->get(1)));
            cc->setParent(bb);
        }
        functionList[functionList.size() - 1]->getPosition()->set(0xf00d1000);

        std::cout << "\n=== After code modifications ===\n";
        module->accept(&dumper);

#if 0
        for(auto f : functionList) {
            for(auto bb : *f) {
                for(auto instr : *bb) {
                    if(instr->hasLink()) {
                        auto old = instr->getLink();

                        auto sym = symbolList->find(old->getTargetAddress());
                        if(!sym) continue;

                        Function *target = 0;
                        for(auto f2 : functionList) {
                            if(f2->getName() == sym->getName()) {
                                target = f2;
                                break;
                            }
                        }
                        if(!target) continue;

                        std::cout << "FOUND REFERENCE from " << f->getName() << " -> " << target->getName() << std::endl;

                        instr->makeLink(
                            old->getSource()->getOffset(),
                            new RelativePosition(target, 0));
                    }
                }
            }
        }

        auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
        Sandbox *sandbox = new SandboxImpl<MemoryBacking, WatermarkAllocator<MemoryBacking>>(backing);

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
            for(auto bb : *f) {
                for(auto instr : *bb) {
                    std::cout << "    ";
                    instr->dump();
                }
            }
        }

#if 1
        for(auto f : functionList) {
            if(f->getName() == "main") {
                std::cout << "main is at " << std::hex << f->getAddress() << "\n";
                int (*mainp)(int, char **) = (int (*)(int, char **))f->getAddress();

                int argc = 1;
                char *argv[] = {(char *)"/dev/null", NULL};
                mainp(argc, argv);
            }
        }
#endif
#endif
    }
    catch(const char *s) {
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }
    return 0;
}
