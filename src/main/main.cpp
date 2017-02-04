#include <iostream>
#include <iomanip>
#include <algorithm>  // for std::max
#include <cstdio>
#include <cstring>
#include "main.h"
#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/disassemble.h"
#include "chunk/dump.h"
#include "pass/resolvecalls.h"
#include "transform/sandbox.h"
#include "log/registry.h"

int main(int argc, char *argv[]) {
    if(argc < 2) return -1;

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        return -2;
    }
    GroupRegistry::getInstance()->dumpSettings();

    try {
        ElfMap elf(argv[1]);
        SymbolList *symbolList = SymbolList::buildSymbolList(&elf);

        auto baseAddr = elf.getCopyBaseAddress();
#if 0
        std::cout << "\n=== Initial code disassembly ===\n";

        for(auto sym : *symbolList) {
            std::cout << "---[" << sym->getName() << "]---\n";
            auto addr = sym->getAddress();
            std::cout << "addr " << std::hex << addr
                << " -> " << std::hex << addr + baseAddr << "\n";
            Disassemble::debug((uint8_t *)(addr + baseAddr), sym->getSize(), addr,
                symbolList);
        }
#endif

        std::cout << "\n=== Creating internal data structures ===\n";

        Module *module = new Module();
        std::vector<Function *> functionList;
        for(auto sym : *symbolList) {
            Function *function = Disassemble::function(sym, baseAddr, symbolList);
            module->getChildren()->add(function);
            functionList.push_back(function);
        }

        ResolveCalls resolver;
        module->accept(&resolver);

        ChunkDumper dumper;

        if(0) {
#ifdef ARCH_X86_64
            auto bb = functionList[3]->getChildren()->getIterable()->get(1);
            Instruction *cc = new Instruction(new DisassembledInstruction(Disassemble::getInsn("\xcc")));
            //cc->setPosition(new RelativePosition(cc, 0));
            cc->setPosition(new SubsequentPosition(bb->getChildren()->getIterable()->get(0)));
            bb->getChildren()->getIterable()->insertAt(1, cc);
            bb->getChildren()->getIterable()->get(2)->setPosition(
                new SubsequentPosition(bb->getChildren()->getIterable()->get(1)));
            cc->setParent(bb);
#elif defined(ARCH_AARCH64)
            Function *func;
            for (auto f : functionList) {
                if (f->getName() == "main") {
                    func = f;
                    break;
                }
            }
            auto bb = func->getChildren()->getIterable()->get(1);
            Instruction *brk = new Instruction(new DisassembledInstruction(Disassemble::getInsn("\x20\x20\x20\xd4"))); //dummy imm. needed for string
            brk->setPosition(new SubsequentPosition(bb->getChildren()->getIterable()->get(0)));
            bb->getChildren()->getIterable()->insertAt(1, brk);
            bb->getChildren()->getIterable()->get(2)->setPosition(
                new SubsequentPosition(bb->getChildren()->getIterable()->get(1)));
            brk->setParent(bb);
#endif
        }
        functionList[functionList.size() - 2]->getPosition()->set(0xf00d1000);

        std::cout << "\n=== After code modifications ===\n";
        module->accept(&dumper);

#if 1
        auto backing = MemoryBacking(10 * 0x1000 * 0x1000);
        Sandbox *sandbox = new SandboxImpl<MemoryBacking, WatermarkAllocator<MemoryBacking>>(backing);

        std::cout << "\n=== Copying code into sandbox ===\n";
        for(auto f : functionList) {
            auto slot = sandbox->allocate(std::max((size_t)0x1000, f->getSize()));
            std::cout << "ALLOC " << slot.getAddress() << " for " << f->getName() << "\n";
            f->getPosition()->set(slot.getAddress());
        }
        for(auto f : functionList) {
            char *output = reinterpret_cast<char *>(f->getAddress());
            std::cout << "writing out " << f->getName() << "\n";
            for(auto b : f->getChildren()->getIterable()->iterable()) {
                for(auto i : b->getChildren()->getIterable()->iterable()) {
                    //f->writeTo(sandbox);
                    i->getSemantic()->writeTo(output);
                    output += i->getSemantic()->getSize();
                }
            }
        }
        sandbox->finalize();

        std::cout << "\n=== After generating new positions ===\n";
        module->accept(&dumper);
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
