#include "resolveplt.h"
#include "elf/symbol.h"
#include "chunk/program.h"
#include "load/emulator.h"
#include "operation/find2.h"

#include "log/log.h"
#include "log/temp.h"

void ResolvePLTPass::visit(Module *module) {
    LOG(1, "resolving PLT for " << module->getName());
    this->module = module;
    recurse(module);
}

void ResolvePLTPass::visit(PLTList *pltList) {
    recurse(pltList);
}

void ResolvePLTPass::visit(PLTTrampoline *pltTrampoline) {
    if(pltTrampoline->getTarget()) return;  // already resolved

    auto symbol = pltTrampoline->getExternalSymbol();
    auto link = PerfectLinkResolver().resolveExternally(symbol, conductor,
        module->getElfSpace(), false);
    if(!link) {
        link = PerfectLinkResolver().resolveExternally(symbol, conductor,
            module->getElfSpace(), true);
    }
    Chunk *target = nullptr;
    if(link) {
        target = link->getTarget();
        delete link;
    }

    if(!target) {
        target = LoaderEmulator::getInstance().findFunction(symbol->getName());
    }
    if(target) {
        LOG(1, "PLT to " << symbol->getName() << " resolved to " <<
            target->getName() << " in " << target->getParent()->getParent()->getName());
        symbol->setResolved(target);

        if(target->getParent()) {
            symbol->setResolvedModule(dynamic_cast<Module *>(
                target->getParent()->getParent()));
        }
    }
    else {
        LOG(1, "unresolved pltTrampoline target "
            << symbol->getName() << " unused?");
    }
}
