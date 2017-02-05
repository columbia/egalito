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
#include "chunk/find.h"
#include "chunk/dump.h"
#include "disasm/disassemble.h"
#include "pass/resolvecalls.h"
#include "pass/resolverelocs.h"
#include "pass/funcptrs.h"
#include "pass/stackxor.h"
#include "transform/sandbox.h"
#include "transform/generator.h"
#include "break/signals.h"
#include "break/breakpoint.h"
#include "log/registry.h"
#include "log/log.h"

extern address_t entry;
extern "C" void _start2(void);

void examineElf(ElfMap *elf);
void setBreakpointsInInterpreter(ElfMap *elf);

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

    return 0;
}

#if 1
void examineElf(ElfMap *elf) {
    SymbolList *symbolList = SymbolList::buildSymbolList(elf);
    SymbolList *dynamicSymbolList = SymbolList::buildDynamicSymbolList(elf);

    LOG(1, "");
    LOG(1, "=== Creating internal data structures ===");

    auto baseAddr = elf->getCopyBaseAddress();
    Module *module = new Module();
    for(auto sym : *symbolList) {
        Function *function = Disassemble::function(sym, baseAddr, symbolList);
        module->getChildren()->add(function);
    }

    ResolveCalls resolver;
    module->accept(&resolver);

    ChunkDumper dumper;
    module->accept(&dumper);

    RelocList *relocList = RelocList::buildRelocList(elf, symbolList, dynamicSymbolList);

    FuncptrsPass funcptrsPass(relocList);
    module->accept(&funcptrsPass);

    ResolveRelocs resolveRelocs(relocList);  // PLT detection
    module->accept(&resolveRelocs);

    module->accept(&dumper);

    StackXOR stackXOR(0x28);
    module->accept(&stackXOR);
    module->accept(&dumper);

    {
        Generator generator;
        auto sandbox = generator.makeSandbox();
        generator.copyCodeToSandbox(elf, module, sandbox);

        LOG(1, "");
        LOG(1, "=== After copying code to new locations ===");
        module->accept(&dumper);

        generator.jumpToSandbox(sandbox, module);
    }
}
#endif
