#include <iostream>
#include <iomanip>
#include <cstring>

#include "elf/elfbuilder.h"
#include "elf/elfspace.h"
#include "elf/elfmap.h"
#include "transform/sandbox.h"
#include "log/registry.h"
#include "log/log.h"


int main(int argc, char *argv[]) {
    if(argc < 2) {
        return -1;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        return -2;
    }

    try {
        ElfSpace *space = new ElfSpace();
        ElfBuilder *elfBuilder = new ElfBuilder(space);

        ElfMap *elf = new ElfMap(argv[1]);
        elfBuilder->setElfMap(elf);

        elfBuilder->buildSymbolList();
        elfBuilder->buildChunkList();
        elfBuilder->buildRelocList();

        auto backing = ElfBacking(space, "gen");
        Sandbox *sandbox = new SandboxImpl<ElfBacking, WatermarkAllocator<ElfBacking> >(backing);
        elfBuilder->setSandbox(sandbox);
        elfBuilder->copyCodeToSandbox();

        elfBuilder->getSandBox()->finalize();

    }
    catch(const char *s) {
        LOG(0, "ERROR: " << s);
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    return 0;
}
