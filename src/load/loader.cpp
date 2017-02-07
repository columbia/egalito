#include <iostream>
#include <iomanip>
#include <cstring>

#include "usage.h"
#include "segmap.h"
#include "elf/elfmap.h"
#include "elf/auxv.h"
#include "chunk/chunk.h"
#include "chunk/chunklist.h"
#include "chunk/dump.h"
#include "conductor/elfbuilder.h"
#include "transform/sandbox.h"
#include "transform/generator.h"
#include "break/signals.h"
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

void examineElf(ElfMap *elf) {
    ElfBuilder builder;
    builder.parseElf(elf);
    builder.findDependencies();
    builder.buildDataStructures();

    auto module = builder.getElfSpace()->getModule();

    {
        Generator generator;
        auto sandbox = generator.makeSandbox();
        generator.copyCodeToSandbox(elf, module, sandbox);

        LOG(1, "");
        LOG(1, "=== After copying code to new locations ===");
        ChunkDumper dumper;
        module->accept(&dumper);

        generator.jumpToSandbox(sandbox, module);
    }
}
