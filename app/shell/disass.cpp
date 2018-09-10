#include <iostream>
#include <cstdio>
#include "disass.h"

#include "analysis/controlflow.h"
#include "conductor/setup.h"
#include "conductor/conductor.h"
#include "chunk/dump.h"
#include "chunk/concrete.h"
#include "chunk/serializer.h"
#include "chunk/gstable.h"  // for testing
#include "chunk/ifunc.h"    // for testing
#include "generate/bingen.h"
#include "operation/find.h"
#include "operation/find2.h"
#include "pass/logcalls.h"
#include "pass/dumptlsinstr.h"
#include "pass/stackxor.h"
#include "pass/noppass.h"
#include "pass/detectnullptr.h"
#include "pass/stackextend.h"
#include "pass/usegstable.h"
#include "pass/collapseplt.h"
#include "pass/promotejumps.h"
#include "pass/reorderpush.h"
#include "pass/retpoline.h"
#include "pass/dumplink.h"
#include "pass/findendbr.h"
#include "pass/endbrenforce.h"
#include "archive/filesystem.h"
#include "dwarf/parser.h"

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

void DisassCommands::registerCommands(CompositeCommand *topLevel) {
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

    topLevel->add("disass2", [&] (Arguments args) {
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        args.shouldHave(2);

        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());

        if(module) {
            Function *func = ChunkFind2()
                .findFunctionInModule(args.get(1).c_str(), module);
            if(func) {
                ChunkDumper dump;
                func->accept(&dump);
            }
            else {
                std::cout << "can't find function \"" << args.front() << "\"\n";
            }
        }
    }, "disassembles a single function (like the GDB command) in the given module");

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

        for(auto module : CIter::modules(conductor->getProgram())) {
            if(findInstrInModule(module, addr)) return;
        }
    }, "disassembles a single instruction");

    topLevel->add("cfgdot", [&] (Arguments args) {
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
            ControlFlowGraph cfg(func);
            cfg.dumpDot();
        }
        else {
            std::cout << "can't find function or address \"" << args.front() << "\"\n";
        }

    }, "prints CFG in dot");

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
        auto sandbox = setup->makeLoaderSandbox();
        setup->moveCodeAssignAddresses(sandbox, true);
    }, "allocates a sandbox and assigns functions new addresses");

    topLevel->add("generate", [&] (Arguments args) {
        args.shouldHave(1);
        auto sandbox = setup->makeFileSandbox(args.front().c_str());
        ////setup->moveCode(sandbox, false);  // calls sandbox->finalize()
        setup->moveCode(sandbox, true);  // calls sandbox->finalize()
    }, "writes out the current code to an ELF file");

#if 0
    // this is currently broken due to Marker rafactoring
    topLevel->add("bin", [&] (Arguments args) {
        args.shouldHave(1);
        BinGen(setup, args.front().c_str()).generate();
    }, "writes out the current image to a binary file");
#endif

    topLevel->add("dumptls", [&] (Arguments args) {
        args.shouldHave(0);
        DumpTLSInstrPass dumptls;
        setup->getConductor()->acceptInAllModules(&dumptls);
    }, "shows all instructions that refer to the TLS register");

    topLevel->add("stackxor", [&] (Arguments args) {
        args.shouldHave(0);
        StackXOR stackXOR(0x28);
        setup->getConductor()->acceptInAllModules(&stackXOR);
    }, "adds XOR to return addresses on the stack");

    topLevel->add("nop-pass", [&] (Arguments args) {
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        NopPass nopPass;
        if (args.size() == 1) {
            Function *func = nullptr;
            func = ChunkFind2(setup->getConductor())
                    .findFunction(args.front().c_str());
            if(func) {
                func->accept(&nopPass);
            }
            else {
                std::cout << "can't find function \"" << args.front() << "\"\n";
            }
        } else if (args.size() == 0) {
            setup->getConductor()->acceptInAllModules(&nopPass);
        } else {
            std::cout << "This pass only takes 0 or 1 arguments." << args.front() << "\"\n";
        }
    }, "adds nop instructions after every non-library instruction");

    topLevel->add("modules", [&] (Arguments args) {
        args.shouldHave(0);
        if(!setup->getConductor() || !setup->getConductor()->getProgram()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        for(auto module : CIter::children(setup->getConductor()->getProgram())) {
            std::cout << module->getName() << std::endl;
        }
    }, "shows a list of all loaded modules");

    topLevel->add("jumptables", [&] (Arguments args) {
        args.shouldHave(0);
        for(auto module : CIter::children(setup->getConductor()->getProgram())) {
            std::cout << "jumptables in " << module->getName() << "...\n";
            ChunkDumper dumper;
            if(auto list = module->getJumpTableList()) {
                list->accept(&dumper) ;
            }
        }
    }, "dumps all jump tables in all modules");

    topLevel->add("jumptables2", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(module) {
            ChunkDumper dumper;
            module->getJumpTableList()->accept(&dumper);
        }
    }, "dumps all jump tables in the given module");

    topLevel->add("functions", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(module) {
            for(auto func : CIter::functions(module)) {
                std::cout << func->getName() << std::endl;
            }
        }
    }, "shows a list of all functions in a module");
    topLevel->add("functions2", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(module) {
            std::vector<Function *> funcList;
            for(auto func : CIter::functions(module)) {
                funcList.push_back(func);
            }

            std::sort(funcList.begin(), funcList.end(),
                [](Function *a, Function *b) {
                    return a->getName() < b->getName();
                });

            for(auto func : funcList) {
                std::printf("0x%08lx %s\n",
                    func->getAddress(), func->getName().c_str());
            }
        }
    }, "shows a sorted list of all functions in a module, with addresses");
    topLevel->add("functions3", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(module) {
            std::vector<Function *> funcList;
            for(auto func : CIter::functions(module)) {
                funcList.push_back(func);
            }

            std::sort(funcList.begin(), funcList.end(),
                [](Function *a, Function *b) {
                    if(a->getAddress() < b->getAddress()) return true;
                    if(a->getAddress() == b->getAddress()) {
                        return a->getName() < b->getName();
                    }
                    return false;
                });

            for(auto func : funcList) {
                std::printf("0x%08lx 0x%08lx %s\n",
                    func->getAddress(), func->getSize(), func->getName().c_str());
            }
        }
    }, "shows a list of all functions in a module, with addresses and sizes");

    topLevel->add("regions", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(module) {
            ChunkDumper dumper;
            module->getDataRegionList()->accept(&dumper);
        }
    }, "shows a list of all data regions in a module");

    topLevel->add("markers", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(module) {
            ChunkDumper dumper;
            module->getMarkerList()->accept(&dumper);
        }
    }, "shows a list of all markers in a module");

    topLevel->add("detectnull", [&] (Arguments args) {
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        args.shouldHave(0);
        DetectNullPtrPass detectNull;
        setup->getConductor()->acceptInAllModules(&detectNull, true);
    }, "runs DetectNullPtrPass to instrument indirect calls");

    topLevel->add("dwarf", [&] (Arguments args) {
        args.shouldHave(0);
        auto elf = setup->getConductor()->getMainSpace()->getElfMap();
        DwarfParser parser(elf);
    }, "parses DWARF unwind info for the main ELF file");

    topLevel->add("extend", [&] (Arguments args) {
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
            StackExtendPass extender(0x10);
            func->accept(&extender);
        }
        else {
            std::cout << "can't find function or address \"" << args.front() << "\"\n";
        }
    }, "extend stack of a single function");

    topLevel->add("archive", [&] (Arguments args) {
        args.shouldHave(1);
        ChunkSerializer serializer;
        serializer.serialize(setup->getConductor()->getProgram(),
            args.front().c_str());
    }, "generates an Egalito archive with the Chunk tree");

    topLevel->add("archive2", [&] (Arguments args) {
        args.shouldHave(0);

        auto program = setup->getConductor()->getProgram();

        ArchiveFileSystem fileSystem;
        auto path = fileSystem.getArchivePathFor(program);
        fileSystem.makeArchivePath(path);

        ChunkSerializer serializer;
        serializer.serialize(program, path.c_str());
    }, "generates an Egalito archive using default filenames");

    topLevel->add("archive3", [&] (Arguments args) {
        args.shouldHave(0);

        ArchiveFileSystem fileSystem;
        auto program = setup->getConductor()->getProgram();
        for(auto module : CIter::modules(program)) {
            auto path = fileSystem.getArchivePathFor(module);
            fileSystem.makeArchivePath(path);

            if(fileSystem.archivePathExists(path)) {
                std::cout << "skipping serialization to ["
                    << path << "]\n";
            }
            else {
                ChunkSerializer serializer;
                serializer.serialize(module, path.c_str());
            }
        }
    }, "generates an Egalito archive using default filenames");

    topLevel->add("usegstable", [&] (Arguments args) {
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        args.shouldHave(0);
        GSTable *gsTable = new GSTable();
        IFuncList *ifuncList = new IFuncList(); // dummy
        UseGSTablePass useGSTable(setup->getConductor(), gsTable, ifuncList);
        setup->getConductor()->acceptInAllModules(&useGSTable, true);
    }, "indirects calls through the GS table");

    topLevel->add("collapseplt", [&] (Arguments args) {
        if(!setup->getConductor()) {
            std::cout << "no ELF files loaded\n";
            return;
        }
        args.shouldHave(0);
        CollapsePLTPass collapsePLT(setup->getConductor());
        setup->getConductor()->acceptInAllModules(&collapsePLT, true);
    }, "changes all instructions that target the PLT to use a direct reference");

    topLevel->add("vtables", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(module && module->getVTableList()) {
            ChunkDumper dumper;
            module->getVTableList()->accept(&dumper);
        }
    }, "shows a list of all vtables in a module");

    topLevel->add("libraries", [&] (Arguments args) {
        args.shouldHave(0);
        auto list = setup->getConductor()->getLibraryList();
        if(!list) {
            std::cout << "no libraries present\n";
            return;
        }
        for(auto library : CIter::children(list)) {
            std::cout << library->getName() << " as "
                << Library::roleAsString(library->getRole()) << std::endl;
            if(!library->getResolvedPath().empty()) {
                std::cout << "    full path "
                    << library->getResolvedPath() << std::endl;
            }
            if(library->getModule()) {
                std::cout << "    loaded as "
                    << library->getModule()->getName() << std::endl;
            }
        }
    }, "shows a list of all recorded libraries");

    topLevel->add("librarypaths", [&] (Arguments args) {
        args.shouldHave(0);
        auto list = setup->getConductor()->getLibraryList();
        if(!list) {
            std::cout << "no libraries present\n";
            return;
        }
        for(auto path : list->getSearchPaths()) {
            std::cout << path << std::endl;
        }
    }, "shows a list of all recorded libraries");

    topLevel->add("externalsyms", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(!module->getExternalSymbolList()) return;
        for(auto xSymbol : CIter::children(module->getExternalSymbolList())) {
            std::cout << xSymbol->getName() << " type " << int(xSymbol->getType())
                << " bind " << int(xSymbol->getBind()) << std::endl;
            if(xSymbol->getResolved()) {
                std::cout << "    resolved to "
                    << xSymbol->getResolved()->getName() << " in "
                    << xSymbol->getResolvedModule()->getName() << std::endl;
            }
        }
    }, "shows a list of all external symbols in a module");

    topLevel->add("unresolvedsyms", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(!module->getExternalSymbolList()) return;
        for(auto xSymbol : CIter::children(module->getExternalSymbolList())) {
            if(!xSymbol->getResolved()) {
                std::cout << xSymbol->getName() << " type " << int(xSymbol->getType())
                    << " bind " << int(xSymbol->getBind()) << std::endl;
            }
        }
    }, "shows a list of all unresolved external symbols in a module");

    topLevel->add("datavars", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        for(auto region : CIter::children(module->getDataRegionList())) {
            for(auto section : CIter::children(region)) {
                std::cout << "inside " << section->getName() << ":\n";
                for(auto var : CIter::children(section)) {
                    std::cout << "var at 0x" << std::hex << var->getAddress()
                        << " name " << var->getName();
                    if(var->getDest() && var->getDest()->getTarget()) {
                        std::cout << " link to " << var->getDest()->getTarget()->getName();
                    }
                    std::cout << std::endl;
                }
            }
        }
    }, "shows a list of all data variables");

    topLevel->add("promotejumps", [&] (Arguments args) {
        PromoteJumpsPass promoteJumps;
        for(auto module : CIter::modules(setup->getConductor()->getProgram())) {
            for(auto func : CIter::functions(module)) {
                func->accept(&promoteJumps);
            }
        }
    }, "promotes tail recursive jumps to 32-bits wide");

    topLevel->add("reorderpush", [&] (Arguments args) {
        args.shouldHave(1);

        Function *func = ChunkFind2(setup->getConductor())
            .findFunction(args.front().c_str());

        if(func) {
            ReorderPush reorder;
            func->accept(&reorder);
        }
        else {
            std::cout << "can't find function \"" << args.front() << "\"\n";
        }
    }, "disassembles a single function (like the GDB command)");

    topLevel->add("retpoline", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(!module) {
            std::cout << "No such module.\n";
            return;
        }

        RetpolinePass retpoline;
        module->accept(&retpoline);
    }, "transforms indirect jumps to use retpolines (Spectre defense)");

    topLevel->add("dumplinks", [&] (Arguments args) {
        args.shouldHave(1);
        auto module = CIter::findChild(setup->getConductor()->getProgram(),
            args.front().c_str());
        if(!module) {
            std::cout << "No such module.\n";
            return;
        }
        DumpLinkPass dumplink;
        module->accept(&dumplink);
    }, "dump all links");

    topLevel->add("findendbr", [&] (Arguments args) {
        FindEndbrPass findendbr;
        if (args.size() == 0) {
            setup->getConductor()->getProgram()->accept(&findendbr);
        }
        else {
            auto module = CIter::findChild(setup->getConductor()->getProgram(),
                args.front().c_str());
            if(!module) {
                std::cout << "No such module.\n";
                return;
            }
            module->accept(&findendbr);
        }
    }, "finds all endbr instruction and prints statistics");

    topLevel->add("endbrenforce", [&] (Arguments args) {
        EndbrEnforcePass pass;
        if (args.size() == 0) {
            setup->getConductor()->getProgram()->accept(&pass);
        }
        else {
            auto module = CIter::findChild(setup->getConductor()->getProgram(),
                args.front().c_str());
            if(!module) {
                std::cout << "No such module.\n";
                return;
            }
            module->accept(&pass);
        }
    }, "add endbr-based control flow integrity checks on indirect jumps");
}
