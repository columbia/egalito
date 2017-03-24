#include <iostream>
#include <iomanip>
#include <cstring>

#include "elfgenmanager.h"
#include "elf/elfmap.h"
#include "elf/elfspace.h"
#include "conductor/conductor.h"
#include "transform/sandbox.h"
#include "transform/generator.h"
#include "log/registry.h"
#include "log/log.h"

int main(int argc, char *argv[]) {
    if(argc < 2) {
        return -1;
    }

    if(!SettingsParser().parseEnvVar("EGALITO_DEBUG")) {
        return -2;
    }
    GroupRegistry::getInstance()->dumpSettings();

    try {
        ElfMap *elf = new ElfMap(argv[1]);
        ElfSpace *space = new ElfSpace(elf, nullptr);
        space->buildDataStructures();

        ElfGenManager manager(space);

        auto backing = ElfBacking(space, "gen");
        manager.setSandbox(new SandboxImpl<ElfBacking, WatermarkAllocator<ElfBacking> >(backing));

        Generator generator;
        manager.copyCodeToSandbox(&generator);
        manager.getSandbox()->finalize();

    }
    catch(const char *s) {
        LOG(0, "ERROR: " << s);
        std::cerr << "Error: " << s;
        if(*s && s[std::strlen(s) - 1] != '\n') std::cerr << '\n';
        return 1;
    }

    return 0;
}
