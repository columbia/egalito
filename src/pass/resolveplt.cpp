#include "resolveplt.h"
#include "elf/symbol.h"
#include "chunk/program.h"
#include "load/emulator.h"
#include "operation/find2.h"

#include "log/log.h"

void ResolvePLTPass::visit(Module *module) {
    this->module = module;
    recurse(module);
}

void ResolvePLTPass::visit(PLTList *pltList) {
    recurse(pltList);
}

void ResolvePLTPass::visit(PLTTrampoline *pltTrampoline) {
    if(pltTrampoline->getTarget()) return;  // already resolved

    auto symbol = pltTrampoline->getExternalSymbol();
    auto found = ChunkFind2(program).findFunction(
        symbol->getName().c_str(), module);

    if(!found) {
        found = LoaderEmulator::getInstance().findFunction(symbol->getName());
    }
    if(found) {
        symbol->setResolved(found);

        if(found->getParent()) {
            symbol->setResolvedModule(dynamic_cast<Module *>(
                found->getParent()->getParent()));
        }
    }
    else {
        LOG(12, "unresolved pltTrampoline target "
            << symbol->getName() << " unused?");
    }
}
