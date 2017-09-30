#include <cassert>
#include <cstring>
#include "injectbridge.h"
#include "elf/reloc.h"
#include "chunk/dataregion.h"
#include "chunk/link.h"
#include "log/log.h"

extern Conductor *egalito_conductor;

void InjectBridgePass::visit(Module *module) {
    for(auto reloc : *relocList) {
        if(auto sym = reloc->getSymbol()) {
            if(!std::strcmp(sym->getName(), "egalito_conductor")) {
                makeLinkToLoaderConductor(module, reloc);
            }
        }
    }
}

void InjectBridgePass::makeLinkToLoaderConductor(Module *module, Reloc *reloc) {
    auto sourceRegion = module->getDataRegionList()->findRegionContaining(
        reloc->getAddress());
    assert(sourceRegion);

    auto link = new SymbolOnlyLink(
        reloc->getSymbol(), reinterpret_cast<address_t>(&egalito_conductor));

    LOG(1, "pointing egalito_conductor to "
        << std::hex << link->getTargetAddress());

    auto var = new DataVariable(sourceRegion, reloc->getAddress(), link);
    sourceRegion->addVariable(var);
}
