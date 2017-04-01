#include <iostream>
#include "disass.h"

#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "chunk/dump.h"
#include "chunk/concrete.h"
#include "chunk/find.h"
#include "chunk/find2.h"

static bool findInstrInModule(Module *module, address_t address) {
    for(auto f : CIter::functions(module)) {
        if(auto i = ChunkFind().findInnermostContaining(f, address)) {
            ChunkDumper dump;
            i->accept(&dump);
            return true;
        }
    }
    return false;
}

void registerDisassCommands(CompositeCommand *topLevel, ConductorSetup *&setup) {
    topLevel->add("disass", [&] (Arguments args) {
        args.shouldHave(1);

        Function *func = nullptr;
        char *end = nullptr;
        auto addr = std::strtol(args.front().c_str(), &end, 16);
        if(args.front().size() > 0 && *end == 0) {
            func = ChunkFind2(setup->getConductor())
                .findFunctionContaining(addr);
        }
        else {
            func = ChunkFind2(setup->getConductor())
                .findFunction(args.front().c_str());
        }

        if(func) {
            ChunkDumper dump;
            func->accept(&dump);
        }
        else {
            std::cout << "can't find function or address \"" << args.front() << "\"\n";
        }
    }, "disassembles a single function (like the GDB command)");
    topLevel->add("x/i", [&] (Arguments args) {
        args.shouldHave(1);
        char *end = nullptr;
        auto addr = std::strtol(args.front().c_str(), &end, 16);
        if(args.front().size() == 0 || *end != 0) {
            std::cout << "invalid address, please use hex\n";
            return;
        }

        auto conductor = setup->getConductor();
        auto mainModule = conductor->getMainSpace()->getModule();
        if(findInstrInModule(mainModule, addr)) return;

        for(auto library : *conductor->getLibraryList()) {
            auto space = library->getElfSpace();
            if(!space) continue;

            if(findInstrInModule(space->getModule(), addr)) return;
        }
    }, "disassembles a single instruction");
}
