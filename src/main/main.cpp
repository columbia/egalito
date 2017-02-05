#include <iostream>
#include <iomanip>
#include <algorithm>  // for std::max
#include <cstdio>
#include <cstring>

#include "elf/elfmap.h"
#include "elf/symbol.h"
#include "chunk/chunk.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "pass/resolvecalls.h"
#include "transform/sandbox.h"
#include "transform/generator.h"
#include "log/registry.h"
#include "log/log.h"

int main(int argc, char *argv[]) {
    if(argc < 2) return -1;

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        return -2;
    }
    GroupRegistry::getInstance()->dumpSettings();

    try {
        ElfMap elf(argv[1]);
        SymbolList *symbolList = SymbolList::buildSymbolList(&elf);

        std::cout << "\n=== Creating internal data structures ===\n";

        auto baseAddr = elf.getCopyBaseAddress();
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

        {
            Generator generator;
            auto sandbox = generator.makeSandbox();
            generator.copyCodeToSandbox(&elf, module, sandbox);

            LOG(1, "");
            LOG(1, "=== After copying code to new locations ===");
            module->accept(&dumper);

            generator.jumpToSandbox(sandbox, module);
        }
    }
    catch(const char *s) {
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }
    return 0;
}
