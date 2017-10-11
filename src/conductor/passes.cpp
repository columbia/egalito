#include "passes.h"

#include "elf/elfspace.h"
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
#include "pass/fallthrough.h"
#include "pass/splitbasicblock.h"
#include "pass/internalcalls.h"
#include "pass/externalcalls.h"
#include "pass/handlerelocs.h"
#include "pass/handledatarelocs.h"
#include "pass/inferlinks.h"
#include "pass/relocdata.h"
#include "pass/jumptablepass.h"
#include "pass/jumptablebounds.h"
#include "pass/jtoverestimate.h"
#include "analysis/jumptable.h"
#include "log/log.h"

void ConductorPasses::newElfPasses(ElfSpace *space) {
    ElfMap *elf = space->getElfMap();
    RelocList *relocList = space->getRelocList();

    Module *module = Disassemble::module(elf,
        space->getSymbolList(), space->getDwarfInfo(),
        space->getDynamicSymbolList(), relocList);
    space->setModule(module);
    module->setElfSpace(space);

    space->setAliasMap(new FunctionAliasMap(module));

    //RUN_PASS(ChunkDumper(), module);

    RUN_PASS(FallThroughFunctionPass(), module);

    DataRegionList::buildDataRegionList(elf, module);

    PLTList::parsePLTList(elf, relocList, module);

    // this needs data regions
    RUN_PASS(HandleDataRelocsInternalStrong(relocList), module);
    RUN_PASS(HandleRelocsStrong(elf, relocList), module);
    RUN_PASS(InternalCalls(), module);

    if(module->getPLTList()) {
        RUN_PASS(ExternalCalls(module->getPLTList()), module);
    }

    RUN_PASS(JumpTablePass(), module);
    RUN_PASS(JumpTableBounds(), module);
    RUN_PASS(JumpTableOverestimate(), module);

    LOG(1, "RUNNING SplitBasicBlock pass");

    // this needs jumptable information and all NormalLinks
    RUN_PASS(SplitBasicBlock(), module);

    // this needs all blocks to be split to basic blocks
    RUN_PASS(InferLinksPass(elf), module);
}

void ConductorPasses::newArchivePasses(Program *program) {
    //RUN_PASS(ChunkDumper(), program);

    RUN_PASS(FallThroughFunctionPass(), program);

    RUN_PASS(InternalCalls(), program);

    for(auto module : CIter::children(program)) {
        if(!module->getDataRegionList()) {
            auto regionList = new DataRegionList();
            module->getChildren()->add(regionList);
            module->setDataRegionList(regionList);
        }
    }
}
