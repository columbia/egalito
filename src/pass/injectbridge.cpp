#include <cassert>
#include <cstring>
#include "injectbridge.h"
#include "conductor/bridge.h"
#include "elf/reloc.h"
#include "chunk/dataregion.h"
#include "chunk/link.h"
#include "operation/mutator.h"
#include "snippet/hook.h"
#include "log/log.h"

class ConductorSetup;
class SandboxFlip;
class IFuncList;

extern address_t egalito_entry;
extern const char *egalito_initial_stack;
extern address_t egalito_init_array[];

extern ConductorSetup *egalito_conductor_setup;
extern Conductor *egalito_conductor;
extern Chunk *egalito_gsCallback;
extern IFuncList *egalito_ifuncList;

void InjectBridgePass::visit(Module *module) {
    auto bridge = LoaderBridge::getInstance();

    for(auto reloc : *relocList) {
        auto sym = reloc->getSymbol();
        if(!sym) continue;

        if(bridge->containsName(sym->getName())) {
            makeLinkToLoaderVariable(module, reloc);
        }
    }
}

void InjectBridgePass::makeLinkToLoaderVariable(Module *module, Reloc *reloc) {
    LOG(1, "[InjectBridge] assigning EgalitoLoaderLink for "
        << reloc->getSymbol()->getName());

    auto address = reloc->getAddress();

    auto sourceRegion = module->getDataRegionList()
        ->findRegionContaining(address);
    assert(sourceRegion);
    auto sourceSection = sourceRegion->findDataSectionContaining(address);

    auto link = new EgalitoLoaderLink(reloc->getSymbol()->getName());

    auto var = new DataVariable(sourceSection, reloc->getAddress(), link);
    //ChunkMutator(sourceSection).append(var);
    sourceSection->getChildren()->add(var);
    sourceRegion->addVariable(var);
}
