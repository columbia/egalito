#include <cassert>
#include <cstring>
#include "injectbridge.h"
#include "elf/reloc.h"
#include "chunk/dataregion.h"
#include "chunk/link.h"
#include "snippet/hook.h"
#include "log/log.h"

class ConductorSetup;
class SandboxFlip;
class IFuncList;

extern ConductorSetup *egalito_conductor_setup;
extern Conductor *egalito_conductor;
extern GSTable *egalito_gsTable;
extern Chunk *egalito_gsCallback;
extern IFuncList *egalito_ifuncList;

void InjectBridgePass::visit(Module *module) {
#define EGALITO_BRIDGE_ENTRY(name) \
    {#name, reinterpret_cast<address_t>(&name)}
    struct {
        const char *name;
        address_t address;
    } list[] = {
        EGALITO_BRIDGE_ENTRY(egalito_conductor_setup),
        EGALITO_BRIDGE_ENTRY(egalito_conductor),
        EGALITO_BRIDGE_ENTRY(egalito_gsTable),
        EGALITO_BRIDGE_ENTRY(egalito_gsCallback),
        EGALITO_BRIDGE_ENTRY(egalito_ifuncList),
        EGALITO_BRIDGE_ENTRY(egalito_hook_instruction_hook),
        EGALITO_BRIDGE_ENTRY(egalito_hook_jit_reset_hook),
    };

    for(auto reloc : *relocList) {
        auto sym = reloc->getSymbol();
        if(!sym) continue;
        for(auto e : list) {
            if(!std::strcmp(sym->getName(), e.name)) {
                makeLinkToLoaderVariable(module, reloc, e.address);
            }
        }
    }
}

void InjectBridgePass::makeLinkToLoaderVariable(Module *module, Reloc *reloc,
    address_t address) {

    LOG(10, "[InjectBridge] pointing " << reloc->getSymbol()->getName()
        << " to " << std::hex << address);

    auto sourceRegion = module->getDataRegionList()->findRegionContaining(
        reloc->getAddress());
    assert(sourceRegion);

    auto link = new SymbolOnlyLink(reloc->getSymbol(), address);

    auto var = new DataVariable(sourceRegion, reloc->getAddress(), link);
    sourceRegion->addVariable(var);
}
