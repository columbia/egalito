#include "passes.h"
#include "conductor.h"

#include "exefile/exefile.h"
#include "elf/symbol.h"
#include "elf/elfdynamic.h"
#include "dwarf/parser.h"
#include "chunk/concrete.h"
#include "chunk/dump.h"
#include "chunk/aliasmap.h"
#include "chunk/tls.h"
#include "chunk/dataregion.h"
#include "operation/find2.h"
#include "disasm/disassemble.h"
#include "pass/collapseplt.h"
#include "pass/fallthrough.h"
#include "pass/nonreturn.h"
#include "pass/splitbasicblock.h"
#include "pass/splitfunction.h"
#include "pass/internalcalls.h"
#include "pass/externalcalls.h"
#include "pass/handlerelocs.h"
#include "pass/inferlinks.h"
#include "pass/jumptablepass.h"
#include "pass/jumptablebounds.h"
#include "pass/jtoverestimate.h"
#include "pass/removepadding.h"
#include "pass/updatelink.h"
#include "pass/collectglobals.h"
#include "analysis/jumptable.h"
#include "log/log.h"
#include "log/temp.h"

Module *ConductorPasses::newExePasses(ExeFile *exeFile) {
    ExeMap *exeMap = exeFile->getMap();

    Module *module = nullptr;
    if(auto elfFile = exeFile->asElf()) {
        module = Disassemble::module(elfFile);
        module->setExeFile(elfFile);

#ifdef ARCH_AARCH64
        // this needs to run even for binaries with symbols
        RUN_PASS(RemovePadding(), module);
#endif
    }
    else if(auto peFile = exeFile->asPE()) {  // PE
        module = Disassemble::module(peFile);
        module->setExeFile(peFile);
    }

    if(auto elfFile = exeFile->asElf()) {
        elfFile->setAliasMap(new FunctionAliasMap(module));

        RUN_PASS(FallThroughFunctionPass(), module);

        DataRegionList::buildDataRegionList(elfFile->getMap(), module);
        module->getChildren()->add(module->getDataRegionList());

        auto relocList = elfFile->getRelocList();
        PLTList::parsePLTList(elfFile->getMap(), relocList, module);

        RUN_PASS(HandleRelocsStrong(elfFile->getMap(), relocList), module);
    }
    else if(auto peFile = exeFile->asPE()) {  // PE
        RUN_PASS(FallThroughFunctionPass(), module);

        DataRegionList::buildDataRegionList(peFile->getMap(), module);
        module->getChildren()->add(module->getDataRegionList());
    }
    RUN_PASS(InternalCalls(), module);

    if(module->getPLTList()) {
        RUN_PASS(ExternalCalls(module->getPLTList()), module);
    }

    // all passes below here depend on data flow analysis and may need to
    // be run multiple times

    // we need to run these before jump table passes, too
    RUN_PASS(SplitBasicBlock(), module);
    RUN_PASS(NonReturnFunction(), module);

    if(auto elfFile = exeFile->asElf()) {
        RUN_PASS(JumpTablePass(), module);
#ifdef ARCH_X86_64
        RUN_PASS(JumpTableBounds(), module);
        RUN_PASS(JumpTableOverestimate(), module);
#endif
#ifdef ARCH_RISCV
        RUN_PASS(JumpTableOverestimate(), module);
#endif

        // run again with jump table information
        RUN_PASS(SplitBasicBlock(), module);
    }

    // need SplitBasicBlock()
    RUN_PASS(NonReturnFunction(), module);
#ifdef ARCH_AARCH64
    if(!exeFile->getSymbolList()) {
        RUN_PASS(SplitFunction(), module);
        RUN_PASS(RemovePadding(), module);
        RUN_PASS(UpdateLink(), module);
    }
#endif
    RUN_PASS(InferLinksPass(), module);

    if(auto peFile = exeFile->asPE()) {  // PE
        RUN_PASS(JumpTablePass(), module);
#ifdef ARCH_X86_64
        RUN_PASS(JumpTableBounds(), module);
        RUN_PASS(JumpTableOverestimate(), module);
#endif

        // run again with jump table information
        RUN_PASS(SplitBasicBlock(), module);
    }

    // this can run pretty much whenever, but let's put it here for now.
    RUN_PASS(CollectGlobalsPass(), module);

    // DataVariables created later in Conductor::resolveData().
    return module;
}

void ConductorPasses::newArchivePasses(Program *program) {
    //RUN_PASS(ChunkDumper(), program);

    for(auto module : CIter::children(program)) {
        if(!module->getDataRegionList()) {
            auto regionList = new DataRegionList();
            module->getChildren()->add(regionList);
            module->setDataRegionList(regionList);
        }
    }
}

void ConductorPasses::newExecutablePasses(Program *program) {
    conductor->fixDataSections(false);
    for(auto module : CIter::children(program)) {
        if(!module->getDataRegionList()) continue;
        for(auto region : CIter::children(module->getDataRegionList())) {
            region->saveDataBytes();
        }
    }
}

void ConductorPasses::newMirrorPasses(Program *program) {
    conductor->fixDataSections(false);
    for(auto module : CIter::children(program)) {
        if(!module->getDataRegionList()) continue;
        for(auto region : CIter::children(module->getDataRegionList())) {
            region->saveDataBytes();
        }
    }
}

void ConductorPasses::reloadedArchivePasses(Module *module) {
    auto elfFile = ExeAccessor::file<ElfExeFile>(module);
    if(elfFile) {
        elfFile->setAliasMap(new FunctionAliasMap(module));
    }
}
