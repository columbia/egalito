#include <iostream>
#include "disass.h"

#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "chunk/dump.h"
#include "chunk/concrete.h"
#include "operation/find.h"
#include "operation/find2.h"
#include "pass/logcalls.h"
#include "pass/dumptlsinstr.h"

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
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        args.shouldHave(1);

        Function *func = nullptr;
        address_t addr;
        if(args.asHex(0, &addr)) {
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
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        args.shouldHave(1);
        address_t addr;
        if(!args.asHex(0, &addr)) {
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

    topLevel->add("logcalls", [&] (Arguments args) {
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        args.shouldHave(0);
        LogCallsPass logCalls(setup->getConductor());
        // false = do not add tracing to Egalito's own functions
        setup->getConductor()->acceptInAllModules(&logCalls, false);
    }, "runs LogCallsPass to instrument function calls");

    topLevel->add("reassign", [&] (Arguments args) {
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        setup->makeLoaderSandbox();
        setup->moveCodeAssignAddresses();
    }, "allocates a sandbox and assigns functions new addresses");

    topLevel->add("generate", [&] (Arguments args) {
        args.shouldHave(1);
        setup->makeFileSandbox(args.front().c_str());
        setup->moveCode();  // calls sandbox->finalize()
    }, "writes out the current code to an ELF file");

    topLevel->add("dumptls", [&] (Arguments args) {
        args.shouldHave(0);
        DumpTLSInstrPass dumptls;
        setup->getConductor()->acceptInAllModules(&dumptls);
    }, "shows all instructions that refer to the TLS register");
}
